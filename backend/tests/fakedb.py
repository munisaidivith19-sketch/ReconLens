"""A small in-memory stand-in for the PyMongo async API used by ReconLens.

Supports only the query/update operators the app actually uses.
"""

import copy
import re
from datetime import datetime
from typing import Any

from bson import ObjectId
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError


def _get_path(doc: Any, path: str) -> Any:
    cur = doc
    for part in path.split("."):
        if isinstance(cur, list) and part.isdigit():
            idx = int(part)
            cur = cur[idx] if idx < len(cur) else None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _set_path(doc: dict, path: str, value: Any) -> None:
    parts = path.split(".")
    cur: Any = doc
    for part in parts[:-1]:
        if isinstance(cur, list):
            cur = cur[int(part)]
        else:
            cur = cur.setdefault(part, {})
    last = parts[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value


def _cmp(a: Any, b: Any) -> int:
    if isinstance(a, datetime) and isinstance(b, datetime):
        a, b = a.timestamp(), b.timestamp()
    return (a > b) - (a < b)


def _match_value(value: Any, cond: Any) -> bool:
    if isinstance(cond, dict) and cond and all(k.startswith("$") for k in cond):
        for op, arg in cond.items():
            if op == "$in":
                if value not in arg:
                    return False
            elif op == "$nin":
                if value in arg:
                    return False
            elif op == "$ne":
                if value == arg:
                    return False
            elif op == "$gte":
                if value is None or _cmp(value, arg) < 0:
                    return False
            elif op == "$gt":
                if value is None or _cmp(value, arg) <= 0:
                    return False
            elif op == "$lte":
                if value is None or _cmp(value, arg) > 0:
                    return False
            elif op == "$lt":
                if value is None or _cmp(value, arg) >= 0:
                    return False
            elif op == "$exists":
                if (value is not None) != arg:
                    return False
            elif op == "$regex":
                if value is None or not re.search(arg, value):
                    return False
            else:
                raise NotImplementedError(op)
        return True
    return value == cond


def matches(doc: dict, flt: dict) -> bool:
    for key, cond in flt.items():
        if key == "$or":
            if not any(matches(doc, sub) for sub in cond):
                return False
            continue
        if not _match_value(_get_path(doc, key), cond):
            return False
    return True


def _apply_update(doc: dict, update: dict, inserting: bool) -> None:
    for op, fields in update.items():
        if op == "$set":
            for k, v in fields.items():
                _set_path(doc, k, copy.deepcopy(v))
        elif op == "$setOnInsert":
            if inserting:
                for k, v in fields.items():
                    _set_path(doc, k, copy.deepcopy(v))
        elif op == "$inc":
            for k, v in fields.items():
                _set_path(doc, k, (_get_path(doc, k) or 0) + v)
        elif op == "$unset":
            for k in fields:
                doc.pop(k, None)
        else:
            raise NotImplementedError(op)


class _Result:
    def __init__(self, **kw: Any):
        self.__dict__.update(kw)


class FakeCursor:
    def __init__(self, docs: list[dict]):
        self._docs = docs

    def sort(self, key: Any, direction: int | None = None) -> "FakeCursor":
        keys = key if isinstance(key, list) else [(key, direction or 1)]
        for k, d in reversed(keys):
            self._docs.sort(
                key=lambda doc, k=k: (_get_path(doc, k) is None, _get_path(doc, k)), reverse=d < 0
            )
        return self

    def skip(self, n: int) -> "FakeCursor":
        self._docs = self._docs[n:]
        return self

    def limit(self, n: int) -> "FakeCursor":
        if n:
            self._docs = self._docs[:n]
        return self

    async def to_list(self, length: int | None = None) -> list[dict]:
        return self._docs[:length] if length else list(self._docs)

    def __aiter__(self):
        self._iter = iter(self._docs)
        return self

    async def __anext__(self) -> dict:
        try:
            return next(self._iter)
        except StopIteration:
            raise StopAsyncIteration from None


def _project(doc: dict, projection: dict | None) -> dict:
    doc = copy.deepcopy(doc)
    if not projection:
        return doc
    excluded = [k for k, v in projection.items() if not v]
    included = [k for k, v in projection.items() if v]
    if included:
        return {k: doc[k] for k in ["_id", *included] if k in doc}
    for k in excluded:
        doc.pop(k, None)
    return doc


class FakeCollection:
    def __init__(self, name: str):
        self.name = name
        self.docs: list[dict] = []
        self.unique: list[tuple[str, ...]] = []

    async def create_index(self, keys: Any, unique: bool = False, **_: Any) -> str:
        fields = tuple(k for k, _ in keys) if isinstance(keys, list) else (keys,)
        if unique and fields not in self.unique:
            self.unique.append(fields)
        return "_".join(fields)

    def _check_unique(self, doc: dict, ignore: dict | None = None) -> None:
        for fields in self.unique:
            key = tuple(_get_path(doc, f) for f in fields)
            for other in self.docs:
                if other is ignore:
                    continue
                if tuple(_get_path(other, f) for f in fields) == key:
                    raise DuplicateKeyError(f"duplicate key {fields}")

    async def insert_one(self, doc: dict) -> _Result:
        doc.setdefault("_id", ObjectId())
        stored = copy.deepcopy(doc)
        self._check_unique(stored)
        self.docs.append(stored)
        return _Result(inserted_id=doc["_id"])

    async def find_one(self, flt: dict | None = None, projection: dict | None = None, sort: Any = None):
        docs = [d for d in self.docs if matches(d, flt or {})]
        if sort:
            docs = FakeCursor(docs).sort(sort)._docs
        return _project(docs[0], projection) if docs else None

    def find(self, flt: dict | None = None, projection: dict | None = None) -> FakeCursor:
        return FakeCursor([_project(d, projection) for d in self.docs if matches(d, flt or {})])

    async def count_documents(self, flt: dict) -> int:
        return sum(1 for d in self.docs if matches(d, flt))

    def _upsert_doc(self, flt: dict) -> dict:
        return {
            k: copy.deepcopy(v) for k, v in flt.items() if not k.startswith("$") and not isinstance(v, dict)
        }

    async def update_one(self, flt: dict, update: dict, upsert: bool = False) -> _Result:
        for d in self.docs:
            if matches(d, flt):
                _apply_update(d, update, inserting=False)
                return _Result(matched_count=1, modified_count=1, upserted_id=None)
        if upsert:
            doc = self._upsert_doc(flt)
            _apply_update(doc, update, inserting=True)
            await self.insert_one(doc)
            return _Result(matched_count=0, modified_count=0, upserted_id=doc["_id"])
        return _Result(matched_count=0, modified_count=0, upserted_id=None)

    async def update_many(self, flt: dict, update: dict) -> _Result:
        n = 0
        for d in self.docs:
            if matches(d, flt):
                _apply_update(d, update, inserting=False)
                n += 1
        return _Result(matched_count=n, modified_count=n)

    async def find_one_and_update(
        self,
        flt: dict,
        update: dict,
        upsert: bool = False,
        return_document: Any = ReturnDocument.BEFORE,
        projection: dict | None = None,
    ):
        for d in self.docs:
            if matches(d, flt):
                before = copy.deepcopy(d)
                _apply_update(d, update, inserting=False)
                return _project(d if return_document == ReturnDocument.AFTER else before, projection)
        if upsert:
            doc = self._upsert_doc(flt)
            _apply_update(doc, update, inserting=True)
            await self.insert_one(doc)
            return _project(doc, projection) if return_document == ReturnDocument.AFTER else None
        return None

    async def replace_one(self, flt: dict, doc: dict, upsert: bool = False) -> _Result:
        for i, d in enumerate(self.docs):
            if matches(d, flt):
                new = copy.deepcopy(doc)
                new.setdefault("_id", d["_id"])
                self.docs[i] = new
                return _Result(matched_count=1)
        if upsert:
            new = copy.deepcopy(doc)
            for k, v in flt.items():
                new.setdefault(k, v)
            await self.insert_one(new)
        return _Result(matched_count=0)

    async def delete_many(self, flt: dict) -> _Result:
        before = len(self.docs)
        self.docs = [d for d in self.docs if not matches(d, flt)]
        return _Result(deleted_count=before - len(self.docs))


class FakeDatabase:
    def __init__(self) -> None:
        self._collections: dict[str, FakeCollection] = {}

    def __getattr__(self, name: str) -> FakeCollection:
        if name.startswith("_"):
            raise AttributeError(name)
        return self[name]

    def __getitem__(self, name: str) -> FakeCollection:
        if name not in self._collections:
            self._collections[name] = FakeCollection(name)
        return self._collections[name]

    async def command(self, *_: Any, **__: Any) -> dict:
        return {"ok": 1}

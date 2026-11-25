# Fingerprint data attribution

The files in this directory (`technologies/*.json`, `categories.json`) are taken from
[enthec/webappanalyzer](https://github.com/enthec/webappanalyzer), an open-source fork of the
Wappalyzer technology fingerprints, at commit `7dba7bf3e8b4f25c6a5b4b2c9f5e7a0e73e6a1bf`
(2026-11-22).

They are licensed under the **GNU General Public License v3.0** (see `LICENSE` in this
directory). They are distributed unmodified as a separate data set; ReconLens reads them at
runtime. Icons and other parts of the upstream repository are not included.

To refresh: download `src/technologies/*.json` and `src/categories.json` from the upstream
repository into this directory and update the commit hash above.

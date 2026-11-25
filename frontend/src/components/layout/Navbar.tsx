import { useState } from 'react'
import { Link, NavLink, useNavigate } from 'react-router'
import { History, LogOut, Menu, Moon, Radar, ScrollText, Sun, X } from 'lucide-react'

import { useAuth } from '../../hooks/useAuth'
import { cn } from '../ui/cn'

type Theme = 'light' | 'dark'
const THEME_KEY = 'reconlens-theme'

function currentTheme(): Theme {
  const set = document.documentElement.dataset.theme
  if (set === 'light' || set === 'dark') return set
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(() => currentTheme())
  const next: Theme = theme === 'dark' ? 'light' : 'dark'
  const toggle = () => {
    document.documentElement.dataset.theme = next
    try {
      localStorage.setItem(THEME_KEY, next)
    } catch {
      /* ignore */
    }
    setTheme(next)
  }
  return (
    <button
      type="button"
      onClick={toggle}
      className="btn btn-ghost btn-icon"
      aria-label={`Switch to ${next} mode`}
      title={`Switch to ${next} mode`}
    >
      {theme === 'dark' ? <Sun size={18} aria-hidden="true" /> : <Moon size={18} aria-hidden="true" />}
    </button>
  )
}

const linkClass = ({ isActive }: { isActive: boolean }) =>
  cn(
    'btn btn-sm btn-ghost text-muted hover:text-fg',
    isActive && 'bg-glass-strong text-fg shadow-[inset_0_1px_0_var(--glass-highlight)]',
  )

export function Navbar() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)

  const onLogout = () => {
    setOpen(false)
    logout()
    navigate('/login')
  }

  const links = user
    ? [
        { to: '/', label: 'New scan', icon: Radar, end: true },
        { to: '/history', label: 'History', icon: History, end: false },
        { to: '/terms', label: 'Responsible use', icon: ScrollText, end: false },
      ]
    : [{ to: '/terms', label: 'Responsible use', icon: ScrollText, end: false }]

  return (
    <header className="no-print sticky top-0 z-40 px-3 pt-3 sm:px-6">
      <nav aria-label="Main" className="glass mx-auto flex max-w-6xl flex-wrap items-center gap-2 rounded-full px-3 py-2">
        <Link to="/" className="mr-auto flex min-w-0 items-center gap-2.5 rounded-full px-2 py-1">
          <img src="/favicon.svg" alt="" width={30} height={30} className="size-[30px] shrink-0" />
          <span className="truncate font-mono text-base font-semibold tracking-tight">
            Recon<span className="text-accent-text">Lens</span>
          </span>
        </Link>

        <div className="hidden items-center gap-1 md:flex">
          {links.map((l) => (
            <NavLink key={l.to} to={l.to} end={l.end} className={linkClass}>
              <l.icon size={16} aria-hidden="true" />
              {l.label}
            </NavLink>
          ))}
        </div>

        <ThemeToggle />

        {user ? (
          <button type="button" onClick={onLogout} className="btn btn-sm hidden md:inline-flex" title={user.email}>
            <LogOut size={16} aria-hidden="true" />
            Sign out
          </button>
        ) : (
          <div className="hidden items-center gap-2 md:flex">
            <Link to="/login" className="btn btn-sm btn-ghost">
              Sign in
            </Link>
            <Link to="/register" className="btn btn-sm btn-primary">
              Create account
            </Link>
          </div>
        )}

        <button
          type="button"
          className="btn btn-ghost btn-icon md:hidden"
          aria-expanded={open}
          aria-controls="mobile-menu"
          aria-label={open ? 'Close menu' : 'Open menu'}
          onClick={() => setOpen((o) => !o)}
        >
          {open ? <X size={20} aria-hidden="true" /> : <Menu size={20} aria-hidden="true" />}
        </button>

        {open && (
          <div id="mobile-menu" onClick={() => setOpen(false)} className="flex w-full flex-col gap-1 border-t border-glass-border pt-2 pb-1 md:hidden">
            {links.map((l) => (
              <NavLink key={l.to} to={l.to} end={l.end} className={({ isActive }) => cn(linkClass({ isActive }), 'justify-start')}>
                <l.icon size={16} aria-hidden="true" />
                {l.label}
              </NavLink>
            ))}
            {user ? (
              <button type="button" onClick={onLogout} className="btn btn-sm btn-ghost justify-start">
                <LogOut size={16} aria-hidden="true" />
                Sign out
              </button>
            ) : (
              <div className="flex flex-wrap gap-2 pt-1">
                <Link to="/login" className="btn btn-sm flex-1">
                  Sign in
                </Link>
                <Link to="/register" className="btn btn-sm btn-primary flex-1">
                  Create account
                </Link>
              </div>
            )}
          </div>
        )}
      </nav>
    </header>
  )
}

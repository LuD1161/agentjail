import * as React from 'react'
import { Link, NavLink } from 'react-router-dom'
import { cn } from '@/lib/utils'

const AgentjailLogo = () => (
  <svg viewBox="0 0 32 32" style={{ height: 28, width: 28, flexShrink: 0 }}>
    <rect width="32" height="32" rx="7" fill="#0A0A0B" />
    <g fill="#F5A623">
      <rect x="14.05" y="11.45" width="1.3" height="1.3" />
      <rect x="15.35" y="11.45" width="1.3" height="1.3" />
      <rect x="16.65" y="11.45" width="1.3" height="1.3" />
      <rect x="12.75" y="12.75" width="1.3" height="1.3" />
      <rect x="14.05" y="12.75" width="1.3" height="1.3" />
      <rect x="15.35" y="12.75" width="1.3" height="1.3" />
      <rect x="16.65" y="12.75" width="1.3" height="1.3" />
      <rect x="17.95" y="12.75" width="1.3" height="1.3" />
      <rect x="11.45" y="14.05" width="1.3" height="1.3" />
      <rect x="12.75" y="14.05" width="1.3" height="1.3" />
      <rect x="14.05" y="14.05" width="1.3" height="1.3" />
      <rect x="15.35" y="14.05" width="1.3" height="1.3" />
      <rect x="16.65" y="14.05" width="1.3" height="1.3" />
      <rect x="17.95" y="14.05" width="1.3" height="1.3" />
      <rect x="19.25" y="14.05" width="1.3" height="1.3" />
      <rect x="11.45" y="15.35" width="1.3" height="1.3" />
      <rect x="12.75" y="15.35" width="1.3" height="1.3" />
      <rect x="14.05" y="15.35" width="1.3" height="1.3" />
      <rect x="15.35" y="15.35" width="1.3" height="1.3" />
      <rect x="16.65" y="15.35" width="1.3" height="1.3" />
      <rect x="17.95" y="15.35" width="1.3" height="1.3" />
      <rect x="19.25" y="15.35" width="1.3" height="1.3" />
      <rect x="11.45" y="16.65" width="1.3" height="1.3" />
      <rect x="12.75" y="16.65" width="1.3" height="1.3" />
      <rect x="14.05" y="16.65" width="1.3" height="1.3" />
      <rect x="15.35" y="16.65" width="1.3" height="1.3" />
      <rect x="16.65" y="16.65" width="1.3" height="1.3" />
      <rect x="17.95" y="16.65" width="1.3" height="1.3" />
      <rect x="19.25" y="16.65" width="1.3" height="1.3" />
      <rect x="12.75" y="17.95" width="1.3" height="1.3" />
      <rect x="14.05" y="17.95" width="1.3" height="1.3" />
      <rect x="15.35" y="17.95" width="1.3" height="1.3" />
      <rect x="16.65" y="17.95" width="1.3" height="1.3" />
      <rect x="17.95" y="17.95" width="1.3" height="1.3" />
      <rect x="14.05" y="19.25" width="1.3" height="1.3" />
      <rect x="15.35" y="19.25" width="1.3" height="1.3" />
      <rect x="16.65" y="19.25" width="1.3" height="1.3" />
    </g>
    <g fill="#FBEFD8">
      <rect x="10.875" y="6.5" width="1.25" height="19" />
      <rect x="13.875" y="6.5" width="1.25" height="19" />
      <rect x="16.875" y="6.5" width="1.25" height="19" />
      <rect x="19.875" y="6.5" width="1.25" height="19" />
    </g>
  </svg>
)

function GitHubStarIcon() {
  return (
    <svg viewBox="0 0 496 512" fill="currentColor" style={{ height: 14, width: 14 }}>
      <path d="M165.9 397.4c0 2-2.3 3.6-5.2 3.6-3.3.3-5.6-1.3-5.6-3.6 0-2 2.3-3.6 5.2-3.6 3-.3 5.6 1.3 5.6 3.6zm-31.1-4.5c-.7 2 1.3 4.3 4.3 4.9 2.6 1 5.6 0 6.2-2s-1.3-4.3-4.3-5.2c-2.6-.7-5.5.3-6.2 2.3zm44.2-1.7c-2.9.7-4.9 2.6-4.6 4.9.3 2 2.9 3.3 5.9 2.6 2.9-.7 4.9-2.6 4.6-4.6-.3-1.9-3-3.2-5.9-2.9zM244.8 8C106.1 8 0 113.3 0 252c0 110.9 69.8 205.8 169.5 239.2 12.8 2.3 17.3-5.6 17.3-12.1 0-6.2-.3-40.4-.3-61.4 0 0-70 15-84.7-29.8 0 0-11.4-29.1-27.8-36.6 0 0-22.9-15.7 1.6-15.4 0 0 24.9 2 38.6 25.8 21.9 38.6 58.6 27.5 72.9 20.9 2.3-16 8.8-27.1 16-33.7-55.9-6.2-112.3-14.3-112.3-110.5 0-27.5 7.6-41.3 23.6-58.9-2.6-6.5-11.1-33.3 2.6-67.9 20.9-6.5 69 27 69 27 20-5.6 41.5-8.5 62.8-8.5s42.8 2.9 62.8 8.5c0 0 48.1-33.6 69-27 13.7 34.7 5.2 61.4 2.6 67.9 16 17.7 25.8 31.5 25.8 58.9 0 96.5-58.9 104.2-114.8 110.5 9.2 7.9 17 22.9 17 46.4 0 33.7-.3 75.4-.3 83.6 0 6.5 4.6 14.4 17.3 12.1C428.2 457.8 496 362.9 496 252 496 113.3 383.5 8 244.8 8z" />
    </svg>
  )
}

function GitHubIssueIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="currentColor" style={{ height: 14, width: 14 }}>
      <path d="M8 9.5a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3Z" />
      <path d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0ZM1.5 8a6.5 6.5 0 1 0 13 0 6.5 6.5 0 0 0-13 0Z" />
    </svg>
  )
}

const navTabClass = ({ isActive }: { isActive: boolean }) =>
  cn(
    'px-3.5 py-1 rounded-t text-[11px] font-semibold uppercase tracking-wider transition-colors',
    isActive
      ? 'text-[#f0f3f6] bg-[#131720] border border-[#3b4252] border-b-transparent'
      : 'text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#1c2333] border border-transparent',
  )

interface LayoutProps {
  children: React.ReactNode
  connected?: boolean
  status?: React.ReactNode
}

export function Layout({ children, connected = true, status }: LayoutProps) {
  return (
    <div className="flex h-screen flex-col overflow-hidden bg-[#131720] text-[#f0f3f6]">
      <header className="flex-none border-b border-[#2a3040] px-5 py-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link
              to="/"
              title="Home"
              className="flex items-center gap-4 transition-opacity hover:opacity-80"
            >
              <AgentjailLogo />
              <span
                className="font-bold tracking-wider text-white"
                style={{ letterSpacing: '0.15em', fontSize: 15 }}
              >
                AGENTJAIL
              </span>
            </Link>
            <nav className="ml-2 flex items-center gap-0" style={{ marginBottom: -1 }}>
              <NavLink to="/" end className={navTabClass}>
                Monitor
              </NavLink>
              <NavLink to="/network" className={navTabClass}>
                Network
              </NavLink>
              <NavLink to="/cost" className={navTabClass}>
                Cost
              </NavLink>
              <NavLink to="/policies" className={navTabClass}>
                Policies
              </NavLink>
            </nav>
            <span
              className={cn('live-dot', !connected && 'opacity-30')}
              title={connected ? 'connected' : 'disconnected'}
            />
            <span className="text-xs text-[#6b7280]">
              {connected ? 'connected' : 'connecting...'}
            </span>
            {status && (
              <>
                <span className="text-xs text-[#4b5563]">|</span>
                {status}
              </>
            )}
          </div>
          <div className="flex items-center gap-3">
            <a
              href="https://github.com/LuD1161/agentjail"
              target="_blank"
              rel="noreferrer"
              title="Star on GitHub"
              className="flex items-center gap-1 rounded border border-[#2a3040] px-2 py-1 text-[11px] text-[#9ca3af] no-underline hover:border-[#545d68] hover:text-white"
            >
              <GitHubStarIcon />
              Star
            </a>
            <a
              href="https://github.com/LuD1161/agentjail/issues/new"
              target="_blank"
              rel="noreferrer"
              title="Report an issue"
              className="flex items-center gap-1 rounded border border-[#2a3040] px-2 py-1 text-[11px] text-[#9ca3af] no-underline hover:border-[#545d68] hover:text-white"
            >
              <GitHubIssueIcon />
              Issue
            </a>
          </div>
        </div>
      </header>
      <div className="min-h-0 flex-1 overflow-hidden">{children}</div>
    </div>
  )
}

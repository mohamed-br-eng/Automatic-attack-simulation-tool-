import { lazy, Suspense, useState, useSyncExternalStore } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { Link, Route, Routes, useLocation } from 'react-router-dom'
import {
  Activity,
  Bot,
  ChevronRight,
  Crosshair,
  FileJson,
  LayoutDashboard,
  Menu,
  Network,
  RefreshCw,
  Shield,
  ShieldAlert,
  X,
} from 'lucide-react'
import { useScans } from './data/store'
import { dataMode } from './data/api'
import { Button } from './components/ui/button'
import { Loading, ErrorState, Empty } from './components/common'
import Scans, { ScanDetail } from './pages/scans'
import Findings, { FindingDetail } from './pages/findings'
import Reports from './pages/reports'
import Assistant from './pages/assistant'
const Overview = lazy(() => import('./pages/overview'))
const NetworkPage = lazy(() => import('./pages/network'))
const navigation = [
  { to: '/', label: 'Overview', icon: LayoutDashboard },
  { to: '/scans', label: 'Scans', icon: Crosshair },
  { to: '/findings', label: 'Findings', icon: ShieldAlert },
  { to: '/network', label: 'Network map', icon: Network },
  { to: '/reports', label: 'Report imports', icon: FileJson },
  { to: '/assistant', label: 'AI assistant', icon: Bot },
]
function isMobile() {
  return window.matchMedia('(max-width: 720px)').matches
}
function subscribeMobile(callback: () => void) {
  const media = window.matchMedia('(max-width: 720px)')
  media.addEventListener('change', callback)
  return () => media.removeEventListener('change', callback)
}
export default function App() {
  const [open, setOpen] = useState(false)
  const { loading, error, refresh } = useScans()
  const location = useLocation()
  const currentItem = navigation.find((n) =>
    n.to === '/'
      ? location.pathname === '/'
      : location.pathname.startsWith(n.to),
  )
  const isFindingDetail =
    location.pathname.startsWith('/scans/') &&
    location.pathname.includes('/findings/')
  const activePath = isFindingDetail ? '/findings' : currentItem?.to
  const current = isFindingDetail
    ? 'Finding detail'
    : (currentItem?.label ?? 'Investigation')
  const mobile = useSyncExternalStore(subscribeMobile, isMobile, () => false)
  const sidebar = (
    <>
      <div className="brand">
        <span>
          <Shield size={23} />
        </span>
        <div>
          SENTINEL<small>ATTACK SIMULATION</small>
        </div>
        <Button
          size="icon"
          variant="ghost"
          className="mobile-close"
          aria-label="Close navigation"
          onClick={() => setOpen(false)}
        >
          <X />
        </Button>
      </div>
      <p className="nav-label">WORKSPACE</p>
      <nav aria-label="Main navigation">
        {navigation.map(({ to, label, icon: Icon }) => (
          <Link
            className={to === activePath ? 'active' : undefined}
            aria-current={to === activePath ? 'page' : undefined}
            to={to}
            key={to}
            onClick={() => setOpen(false)}
          >
            <Icon size={19} />
            <span>{label}</span>
            {to === '/assistant' && (
              <span className="nav-planned">Unavailable</span>
            )}
          </Link>
        ))}
      </nav>
      <div className="sidebar-bottom">
        <div>
          <span className="live-dot" />{' '}
          {dataMode === 'mock' ? 'Demo workspace' : 'API workspace'}
        </div>
        <p>
          {dataMode === 'mock'
            ? 'Static fixtures + local imports'
            : 'Backend connection configured'}
        </p>
        <small>
          Automatic Attacks Simulation Tool
          <br />
          P5 · Interface & intelligence
        </small>
      </div>
    </>
  )
  return (
    <Dialog.Root open={open && mobile} onOpenChange={setOpen}>
      <div className="app-shell">
        <a className="skip-link" href="#main-content">
          Skip to content
        </a>
        {mobile ? (
          <Dialog.Portal>
            <Dialog.Overlay className="nav-backdrop" />
            <Dialog.Content
              className="sidebar is-open"
              aria-describedby={undefined}
            >
              <Dialog.Title className="sr-only">
                Workspace navigation
              </Dialog.Title>
              {sidebar}
            </Dialog.Content>
          </Dialog.Portal>
        ) : (
          <aside className="sidebar">{sidebar}</aside>
        )}

        <div className="main-shell">
          <header className="topbar">
            <div>
              <Dialog.Trigger asChild>
                <Button
                  size="icon"
                  variant="ghost"
                  className="mobile-menu"
                  aria-label="Open navigation"
                  aria-expanded={open}
                  onClick={() => setOpen(true)}
                >
                  <Menu />
                </Button>
              </Dialog.Trigger>
              <span className="breadcrumb">
                Workspace <ChevronRight size={14} /> <strong>{current}</strong>
              </span>
            </div>
            <div>
              <span className="environment">
                <Activity size={14} />
                {dataMode === 'mock' ? 'DEMO DATA' : 'API MODE'}
              </span>
              <Button
                size="icon"
                variant="ghost"
                aria-label="Refresh scan data"
                onClick={refresh}
              >
                <RefreshCw />
              </Button>
              <span className="avatar" aria-label="P5 workspace">
                P5
              </span>
            </div>
          </header>
          <main id="main-content" tabIndex={-1}>
            {dataMode === 'mock' && (
              <div className="demo-banner">
                <span className="live-dot" /> Demo data{' '}
                <span>
                  Static fixtures are loaded. Imported reports are labeled
                  separately.
                </span>
              </div>
            )}
            {error && <ErrorState error={error} retry={refresh} />}
            <Suspense fallback={<Loading />}>
              {loading ? (
                <Loading />
              ) : (
                <Routes>
                  <Route path="/" element={<Overview />} />
                  <Route path="/scans" element={<Scans />} />
                  <Route path="/scans/:scanId" element={<ScanDetail />} />
                  <Route
                    path="/scans/:scanId/findings/:findingId"
                    element={<FindingDetail />}
                  />
                  <Route path="/findings" element={<Findings />} />
                  <Route path="/reports" element={<Reports />} />
                  <Route path="/assistant" element={<Assistant />} />
                  <Route path="/network" element={<NetworkPage />} />
                  <Route
                    path="*"
                    element={
                      <Empty
                        title="Page not found"
                        detail="Use the workspace navigation to return to your scans."
                      />
                    }
                  />
                </Routes>
              )}
            </Suspense>
            <footer>
              <span>
                <Shield size={13} /> Built for authorized lab investigations
              </span>
              <span>P5 dashboard · local workspace</span>
            </footer>
          </main>
        </div>
      </div>
    </Dialog.Root>
  )
}

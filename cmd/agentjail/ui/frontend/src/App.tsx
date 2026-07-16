// Bust stale react-resizable-panels localStorage cache.
// Increment this version whenever panel defaults change.
const PANEL_LAYOUT_VERSION = 'v6'
const PANEL_VERSION_KEY = 'aj-panel-version'
if (typeof window !== 'undefined' && localStorage.getItem(PANEL_VERSION_KEY) !== PANEL_LAYOUT_VERSION) {
  for (const key of Object.keys(localStorage)) {
    if (key.startsWith('react-resizable-panels:')) {
      localStorage.removeItem(key)
    }
  }
  localStorage.setItem(PANEL_VERSION_KEY, PANEL_LAYOUT_VERSION)
}

import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TooltipProvider } from '@/components/ui/tooltip'
import { NetworkPage } from './pages/network'
import { MonitorPage } from './pages/monitor'
import { PoliciesPage } from './pages/policies'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider delayDuration={200}>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<MonitorPage />} />
            <Route path="/policies" element={<PoliciesPage />} />
            <Route path="/network" element={<NetworkPage />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  )
}

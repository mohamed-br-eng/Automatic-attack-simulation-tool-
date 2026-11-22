import { createContext, useContext, useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { createApi, type DashboardApi } from './api'
import type { Scan } from './schema'
const Context = createContext<{
  scans: Scan[]
  loading: boolean
  error: Error | null
  addScan: (scan: Scan) => void
  clearImports: () => void
  refresh: () => void
} | null>(null)
export function ScanProvider({
  children,
  api: suppliedApi,
}: {
  children: ReactNode
  api?: DashboardApi
}) {
  const [api] = useState(() => suppliedApi ?? createApi())
  const [imports, setImports] = useState<Scan[]>([])
  const query = useQuery({
    queryKey: ['scans'],
    queryFn: ({ signal }) => api.listScans(signal),
    retry: 1,
    staleTime: 30000,
  })
  return (
    <Context.Provider
      value={{
        scans: [...imports, ...(query.data ?? [])],
        loading: query.isPending,
        error: query.error,
        addScan: (scan) =>
          setImports((previous) => [
            { ...scan, id: `import-${crypto.randomUUID()}` },
            ...previous,
          ]),
        clearImports: () => setImports([]),
        refresh: () => {
          void query.refetch()
        },
      }}
    >
      {children}
    </Context.Provider>
  )
}
// Kept alongside its provider so the import store has one ownership boundary.
// eslint-disable-next-line react-refresh/only-export-components
export function useScans() {
  const value = useContext(Context)
  if (!value) throw new Error('ScanProvider is required')
  return value
}

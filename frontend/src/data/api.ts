import { z } from 'zod'
import { scanSchema, topologySchema, type Scan, type Topology } from './schema'
import { mockScans } from './mock'
export interface DashboardApi {
  listScans(signal?: AbortSignal): Promise<Scan[]>
  getTopology(signal?: AbortSignal): Promise<Topology | null>
}
export function createHttpApi(
  baseUrl: string,
  fetcher: typeof fetch = fetch,
): DashboardApi {
  const base = baseUrl.replace(/\/$/, '')
  async function get(path: string, signal?: AbortSignal) {
    const response = await fetcher(`${base}${path}`, {
      signal,
      headers: { Accept: 'application/json' },
    })
    if (!response.ok)
      throw new Error(
        `Backend request failed (${response.status}). Check the API URL, authentication, and CORS configuration.`,
      )
    return response.json() as Promise<unknown>
  }
  return {
    listScans: async (signal) =>
      z.array(scanSchema).parse(await get('/scans', signal)),
    getTopology: async (signal) => {
      const response = await fetcher(`${base}/topology`, {
        signal,
        headers: { Accept: 'application/json' },
      })
      if (response.status === 404 || response.status === 204) return null
      if (!response.ok)
        throw new Error(`Topology request failed (${response.status})`)
      return topologySchema.parse(await response.json())
    },
  }
}
export function createApi(
  mode = import.meta.env.VITE_DATA_SOURCE ?? 'mock',
  baseUrl = import.meta.env.VITE_API_BASE_URL ?? '',
): DashboardApi {
  if (mode === 'mock')
    return { listScans: async () => mockScans(), getTopology: async () => null }
  if (mode !== 'api') throw new Error('VITE_DATA_SOURCE must be mock or api')
  return createHttpApi(baseUrl)
}
export const dataMode = import.meta.env.VITE_DATA_SOURCE ?? 'mock'

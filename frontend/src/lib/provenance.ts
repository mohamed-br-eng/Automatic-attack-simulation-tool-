import type { Scan } from '@/data/schema'
export const sourceLabels: Record<Scan['source'], string> = {
  mock: 'Demo',
  p4: 'P4 import',
  p3: 'P3 import',
  api: 'API',
}
export function matchesSource(source: Scan['source'], filter: string) {
  return (
    filter === 'all' ||
    (filter === 'imported'
      ? source === 'p3' || source === 'p4'
      : source === filter)
  )
}

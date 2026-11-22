import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import App from '@/App'
import { ScanProvider } from '@/data/store'
import { mockScans } from '@/data/mock'
import { makeReport } from '@/data/adapters'
import type { DashboardApi } from '@/data/api'
function mount(
  path = '/findings',
  api: DashboardApi = {
    listScans: async () => mockScans(),
    getTopology: async () => null,
  },
) {
  return render(
    <QueryClientProvider
      client={
        new QueryClient({
          defaultOptions: { queries: { retry: false, gcTime: 0 } },
        })
      }
    >
      <MemoryRouter initialEntries={[path]}>
        <ScanProvider api={api}>
          <App />
        </ScanProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}
function jsonFile(text: string, name = 'report.json') {
  const file = new File([text], name, { type: 'application/json' })
  Object.defineProperty(file, 'text', { value: async () => text })
  return file
}
describe('dashboard workflows', () => {
  it('places priority findings before charts and keeps source-scoped metrics consistent', async () => {
    const user = userEvent.setup()
    const imported = {
      ...mockScans()[0],
      id: 'imported-scan',
      source: 'p4' as const,
    }
    mount('/', {
      listScans: async () => [...mockScans(), imported],
      getTopology: async () => null,
    })
    await screen.findByRole('heading', { name: 'Overview' }, { timeout: 5000 })
    const priority = screen.getByRole('region', { name: /Priority review/ })
    const chart = screen.getByRole('region', { name: 'Severity distribution' })
    expect(
      priority.compareDocumentPosition(chart) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy()
    await user.selectOptions(
      screen.getByLabelText('Overview data source'),
      'imported',
    )
    expect(within(priority).getByText('6 findings')).toBeInTheDocument()
    const metric = within(screen.getByLabelText('Operational metrics'))
      .getByText('Findings')
      .closest('article')!
    expect(within(metric).getByText('6')).toBeInTheDocument()
    expect(within(chart).getByRole('img')).toHaveAccessibleName(
      'CRITICAL: 1, HIGH: 2, MEDIUM: 1, LOW: 1, INFO: 1',
    )
    expect(within(priority).getAllByText('P4 import')).toHaveLength(5)
    expect(within(priority).queryByText('Demo')).not.toBeInTheDocument()
  })
  it('combines target/source filters, displays EPSS and resets filters', async () => {
    const user = userEvent.setup()
    mount()
    await screen.findByLabelText('Filter target')
    await user.selectOptions(
      screen.getByLabelText('Filter target'),
      'http://127.0.0.1:8080/login',
    )
    expect(screen.getByRole('status')).toHaveTextContent('1 of 8 findings')
    expect(
      screen.getAllByRole('link', { name: 'Weak credentials accepted' }),
    ).toHaveLength(1)
    await user.selectOptions(
      screen.getByLabelText('Filter data source'),
      'imported',
    )
    expect(
      screen.getByRole('heading', { name: 'No findings match' }),
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(screen.getByRole('status')).toHaveTextContent('8 of 8 findings')
    expect(screen.getAllByText('82.00%')).toHaveLength(2)
    expect(screen.getAllByText('Unavailable').length).toBeGreaterThan(0)
  })
  it('paginates findings and returns to page one after changing filters', async () => {
    const user = userEvent.setup()
    const scan = mockScans()[0]
    const findings = Array.from({ length: 14 }, (_, i) => ({
      ...scan.report.findings[0],
      id: `page-${i}`,
      title: `Finding ${String(i).padStart(2, '0')}`,
    }))
    scan.report = makeReport(findings, scan.report.meta)
    mount('/findings', {
      listScans: async () => [scan],
      getTopology: async () => null,
    })
    await screen.findByLabelText('Search findings')
    expect(screen.getByText('1–10 of 14 · page 1 of 2')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Next' }))
    expect(screen.getByText('11–14 of 14 · page 2 of 2')).toBeInTheDocument()
    await user.type(screen.getByLabelText('Search findings'), 'Finding 00')
    expect(screen.getByText('1–1 of 1 · page 1 of 1')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled()
  })
  it('opens accessible mobile navigation and dismisses it with Escape', async () => {
    vi.spyOn(window, 'matchMedia').mockImplementation((query) => ({
      matches: true,
      media: query,
      onchange: null,
      addListener() {},
      removeListener() {},
      addEventListener() {},
      removeEventListener() {},
      dispatchEvent: () => false,
    }))
    const user = userEvent.setup()
    mount('/findings')
    await screen.findByRole('heading', { name: 'Vulnerability findings' })
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Open navigation' }))
    expect(
      screen.getByRole('dialog', { name: 'Workspace navigation' }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Close navigation' }),
    ).toHaveFocus()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Open navigation' }),
    ).toHaveFocus()
  })
  it('filters findings and opens the correct finding detail', async () => {
    const user = userEvent.setup()
    mount()
    await screen.findByRole('heading', { name: 'Vulnerability findings' })
    await user.type(
      screen.getByRole('textbox', { name: 'Search findings' }),
      'SQL injection',
    )
    expect(
      screen.getAllByRole('link', { name: 'SQL injection in product search' }),
    ).toHaveLength(1)
    expect(
      screen.queryByRole('link', { name: 'Weak credentials accepted' }),
    ).not.toBeInTheDocument()
    await user.click(
      screen.getByRole('link', { name: 'SQL injection in product search' }),
    )
    expect(
      await screen.findByRole('heading', {
        name: 'SQL injection in product search',
      }),
    ).toBeInTheDocument()
    expect(
      screen.getByText('Use parameterized queries and validate input types.'),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('link', { name: 'Findings' }),
    ).toHaveAttribute('aria-current', 'page')
  })
  it('shows an empty state when filters match nothing', async () => {
    const user = userEvent.setup()
    mount()
    await screen.findByRole('textbox', { name: 'Search findings' })
    await user.selectOptions(screen.getByLabelText('Filter severity'), 'INFO')
    await user.type(screen.getByLabelText('Search findings'), 'no matches')
    expect(
      screen.getByRole('heading', { name: 'No findings match' }),
    ).toBeInTheDocument()
  })
  it('imports P4 JSON and exposes its results in scan history', async () => {
    const user = userEvent.setup()
    mount('/reports')
    const input = await screen.findByLabelText('Import JSON report')
    const report = structuredClone(mockScans()[0].report)
    report.meta.scan_id = 'p4-real-import'
    await user.upload(input, jsonFile(JSON.stringify(report)))
    expect(await screen.findByRole('status')).toHaveTextContent(
      'Imported 6 findings',
    )
    await user.click(screen.getByRole('link', { name: 'View scans →' }))
    expect(
      await screen.findByRole('link', { name: 'p4-real-import' }),
    ).toBeInTheDocument()
    await user.click(screen.getByRole('link', { name: 'p4-real-import' }))
    expect(
      await screen.findByRole('heading', { name: 'Scan timeline' }),
    ).toBeInTheDocument()
    expect(screen.getByText('Not provided in report')).toBeInTheDocument()
  })
  it('shows invalid JSON errors and allows a corrected file', async () => {
    const user = userEvent.setup()
    mount('/reports')
    const input = await screen.findByLabelText('Import JSON report')
    await user.upload(input, jsonFile('{'))
    expect(await screen.findByRole('alert')).toBeInTheDocument()
    await user.upload(input, jsonFile(JSON.stringify(mockScans()[0].report)))
    expect(await screen.findByRole('status')).toHaveTextContent(
      'Imported 6 findings',
    )
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
  it('renders imported HTML evidence as inert text', async () => {
    const user = userEvent.setup()
    mount('/reports')
    const input = await screen.findByLabelText('Import JSON report')
    const report = structuredClone(mockScans()[0].report)
    report.meta.scan_id = 'text-only'
    report.findings[0].evidence = '<img src=x onerror=alert(1)>'
    await user.upload(input, jsonFile(JSON.stringify(report)))
    await screen.findByRole('status')
    await user.click(screen.getByRole('link', { name: 'View scans →' }))
    await user.click(await screen.findByRole('link', { name: 'text-only' }))
    await user.click(
      screen.getAllByRole('link', {
        name: 'SQL injection in product search',
      })[0],
    )
    expect(
      await screen.findByText('<img src=x onerror=alert(1)>'),
    ).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()
  })
  it('disables assistant input and identifies all AI features as unavailable', async () => {
    mount('/assistant')
    expect(
      await screen.findByRole('heading', { name: 'AI assistant' }),
    ).toBeInTheDocument()
    expect(
      screen.getByLabelText('Assistant message (unavailable)'),
    ).toBeDisabled()
    expect(
      screen.getByRole('button', { name: 'Send message (unavailable)' }),
    ).toBeDisabled()
  })
  it('shows loading then backend errors while leaving imports usable', async () => {
    let reject: (error: Error) => void = () => {}
    const pending = new Promise<ReturnType<typeof mockScans>>((_, fail) => {
      reject = fail
    })
    mount('/reports', {
      listScans: () => pending,
      getTopology: async () => null,
    })
    expect(screen.getByRole('status')).toHaveTextContent('Loading scan data')
    reject(new Error('API offline'))
    await waitFor(
      () => expect(screen.getByRole('alert')).toHaveTextContent('API offline'),
      { timeout: 4000 },
    )
    expect(screen.getByLabelText('Import JSON report')).toBeEnabled()
  })
  it('handles missing detail routes', async () => {
    mount('/scans/missing')
    expect(
      await screen.findByRole('heading', { name: 'Scan not found' }),
    ).toBeInTheDocument()
  })
})

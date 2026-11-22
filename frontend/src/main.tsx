import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ScanProvider } from './data/store'
import App from './App'
import './styles.css'
const client = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false } },
})
ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={client}>
      <BrowserRouter>
        <ScanProvider>
          <App />
        </ScanProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
)

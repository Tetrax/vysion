import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import AdminApp from './AdminApp'
import App from './App'

const view = window.location.pathname.startsWith('/admin') ? <AdminApp /> : <App />

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {view}
  </StrictMode>,
)

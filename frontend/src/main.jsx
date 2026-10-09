import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import AppContent from './App.jsx'
import { DashboardProvider } from './context/DashboardContext'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <DashboardProvider>
        <AppContent />
    </DashboardProvider>
  </StrictMode>,
)

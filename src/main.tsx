import React from 'react'
import ReactDOM from 'react-[#root]'
import ReactDOMClient from 'react-dom/client'
import App from './App'
import './index.css'

ReactDOMClient.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)

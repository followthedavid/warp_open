import { createApp } from 'vue'
import './style.css'
import App from './App.vue'

const app = createApp(App)

// Global error handler to prevent blank screens
app.config.errorHandler = (err, instance, info) => {
  console.error('[Vue Error]', err)
  console.error('[Vue Error Info]', info)

  // Show error in the UI if possible
  const appEl = document.getElementById('app')
  if (appEl && !document.querySelector('.vue-error-boundary')) {
    const errorDiv = document.createElement('div')
    errorDiv.className = 'vue-error-boundary'
    errorDiv.style.cssText = `
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      background: #1e1e1e;
      border: 1px solid #ef4444;
      padding: 24px;
      border-radius: 8px;
      color: #d4d4d4;
      max-width: 600px;
      font-family: 'SF Mono', Monaco, monospace;
      z-index: 9999;
    `
    errorDiv.innerHTML = `
      <h3 style="color: #ef4444; margin-bottom: 12px;">Application Error</h3>
      <p style="margin-bottom: 8px;">${err.message || 'Unknown error'}</p>
      <pre style="background: #0d0d0d; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 12px; max-height: 200px; overflow-y: auto;">${err.stack || ''}</pre>
      <button onclick="location.reload()" style="margin-top: 16px; background: #3b82f6; border: none; color: white; padding: 8px 16px; border-radius: 4px; cursor: pointer;">
        Reload Application
      </button>
    `
    appEl.appendChild(errorDiv)
  }
}

// Warn handler for development
app.config.warnHandler = (msg, instance, trace) => {
  console.warn('[Vue Warning]', msg)
  if (trace) console.warn('[Vue Warning Trace]', trace)
}

app.mount('#app')

// src/stores/alertStore.js
import { reactive } from 'vue'

export const alertStore = reactive({
  alerts: [],
  alertHistory: new Set(),
  maxVisible: 5,
  defaultAutoResolve: { low: 3000, medium: 5000, high: null }, // ms, null = manual
  phaseAutoResolve: {
    phase1: 2000,
    phase2: 4000,
    phase3: 8000,
    phase4: 5000,
    phase5: null, // stay until manual
    phase6: null  // phase 6 plans may run for hours/days
  },

  addAlert(alert) {
    if (!this.alertHistory.has(alert.key)) {
      const duration = this.phaseAutoResolve[alert.phase] ?? this.defaultAutoResolve[alert.severity]
      const newAlert = { 
        ...alert, 
        resolved: false,
        createdAt: Date.now(),
        countdown: duration ? duration / 1000 : null, // seconds
        initialCountdown: duration ? duration / 1000 : null
      }

      this.alerts.push(newAlert)
      this.alertHistory.add(alert.key)
      this.sortAlerts()
      this.trimAlerts()
      this.scheduleCountdown(newAlert, duration)
    }
  },

  scheduleCountdown(alert, duration) {
    if (!duration) return
    const interval = setInterval(() => {
      if (alert.countdown > 0) {
        alert.countdown -= 1
      } else {
        clearInterval(interval)
        this.resolveAlert(alert.key)
      }
    }, 1000)
  },

  resolveAlert(key) {
    const idx = this.alerts.findIndex(a => a.key === key)
    if (idx !== -1 && !this.alerts[idx].resolved) {
      this.alerts[idx].resolved = true
      setTimeout(() => this.removeAlert(key), 1000)
    }
  },

  updateAlert(key, updates) {
    const idx = this.alerts.findIndex(a => a.key === key)
    if (idx !== -1) {
      this.alerts[idx] = { ...this.alerts[idx], ...updates }
      this.sortAlerts()
    }
  },

  removeAlert(key) {
    const idx = this.alerts.findIndex(a => a.key === key)
    if (idx !== -1) {
      this.alertHistory.delete(this.alerts[idx].key)
      this.alerts.splice(idx, 1)
    }
  },

  sortAlerts() {
    const sev = { high: 3, medium: 2, low: 1 }
    this.alerts.sort((a, b) => {
      return (sev[b.severity] - sev[a.severity]) || (b.createdAt - a.createdAt)
    })
  },

  trimAlerts() {
    while (this.alerts.length > this.maxVisible) {
      const oldest = this.alerts[this.alerts.length - 1]
      this.removeAlert(oldest.key)
    }
  }
})

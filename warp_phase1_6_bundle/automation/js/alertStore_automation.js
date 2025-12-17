// alertStore_automation.js
// Real-time anomaly detection and alert management for Warp Phase 1-6

import { reactive, computed } from 'vue';

// Alert severity levels
export const AlertSeverity = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

// Alert store - reactive state management
export const alertStore = reactive({
  alerts: [],
  maxAlerts: 100,
  
  addAlert(message, severity = AlertSeverity.MEDIUM, metadata = {}) {
    // Prevent duplicate alerts
    const isDuplicate = this.alerts.some(a => 
      a.message === message && 
      Date.now() - a.timestamp.getTime() < 60000 // Within 1 minute
    );
    
    if (isDuplicate) {
      return;
    }
    
    const alert = {
      id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      message,
      severity,
      metadata,
      timestamp: new Date(),
      acknowledged: false
    };
    
    this.alerts.unshift(alert);
    
    // Maintain max alerts limit
    if (this.alerts.length > this.maxAlerts) {
      this.alerts = this.alerts.slice(0, this.maxAlerts);
    }
    
    // Emit event for external listeners
    window.dispatchEvent(new CustomEvent('warp:alert', { detail: alert }));
    
    console.log(`[ALERT ${severity.toUpperCase()}] ${message}`, metadata);
  },
  
  removeAlert(alertId) {
    const index = this.alerts.findIndex(a => a.id === alertId);
    if (index !== -1) {
      this.alerts.splice(index, 1);
    }
  },
  
  acknowledgeAlert(alertId) {
    const alert = this.alerts.find(a => a.id === alertId);
    if (alert) {
      alert.acknowledged = true;
    }
  },
  
  clearAll() {
    this.alerts = [];
  },
  
  clearAcknowledged() {
    this.alerts = this.alerts.filter(a => !a.acknowledged);
  },
  
  getAlertsBySeverity(severity) {
    return this.alerts.filter(a => a.severity === severity);
  },
  
  getUnacknowledgedCount() {
    return this.alerts.filter(a => !a.acknowledged).length;
  }
});

// Computed properties for Vue components
export const alertStats = computed(() => ({
  total: alertStore.alerts.length,
  unacknowledged: alertStore.getUnacknowledgedCount(),
  critical: alertStore.getAlertsBySeverity(AlertSeverity.CRITICAL).length,
  high: alertStore.getAlertsBySeverity(AlertSeverity.HIGH).length,
  medium: alertStore.getAlertsBySeverity(AlertSeverity.MEDIUM).length,
  low: alertStore.getAlertsBySeverity(AlertSeverity.LOW).length
}));

// ===== TIER 1: Anomaly Detection Functions =====

/**
 * Monitor plans for stalls (pending with no progress)
 * @param {Array} plans - Array of plan objects
 * @param {number} stallThreshold - Time in seconds before considered stalled
 */
export function monitorStalledPlans(plans, stallThreshold = 60) {
  if (!plans || !Array.isArray(plans)) return;
  
  const now = Date.now();
  
  plans.forEach(plan => {
    if (plan.status === "Pending" && plan.progress_index > 0) {
      const stalledTime = plan.stalled_duration || 0;
      
      if (stalledTime > stallThreshold) {
        alertStore.addAlert(
          `Plan ${plan.id} has been stalled for ${Math.round(stalledTime / 60)} minutes`,
          AlertSeverity.HIGH,
          {
            plan_id: plan.id,
            stalled_duration: stalledTime,
            progress_index: plan.progress_index
          }
        );
      }
    }
  });
}

/**
 * Monitor batch execution failures
 * @param {Array} batches - Array of batch objects
 */
export function monitorBatchFailures(batches) {
  if (!batches || !Array.isArray(batches)) return;
  
  batches.forEach(batch => {
    if (batch.status === "Failed" && !batch.alerted) {
      alertStore.addAlert(
        `Batch ${batch.id} failed: ${batch.error_message || 'Unknown error'}`,
        AlertSeverity.CRITICAL,
        {
          batch_id: batch.id,
          phase: batch.phase,
          error: batch.error_message
        }
      );
      batch.alerted = true; // Mark as alerted to prevent duplicates
    }
  });
}

/**
 * Monitor agent health and workload
 * @param {Array} agents - Array of agent objects
 */
export function monitorAgentHealth(agents) {
  if (!agents || !Array.isArray(agents)) return;
  
  agents.forEach(agent => {
    // Check for overloaded agents
    if (agent.active_tasks && agent.active_tasks.length > 10) {
      alertStore.addAlert(
        `Agent ${agent.name} is overloaded with ${agent.active_tasks.length} tasks`,
        AlertSeverity.MEDIUM,
        {
          agent_id: agent.id,
          agent_name: agent.name,
          task_count: agent.active_tasks.length
        }
      );
    }
    
    // Check for idle agents when work is pending
    if (agent.status === "idle" && agent.idle_duration > 300) { // 5 minutes
      alertStore.addAlert(
        `Agent ${agent.name} has been idle for ${Math.round(agent.idle_duration / 60)} minutes`,
        AlertSeverity.LOW,
        {
          agent_id: agent.id,
          agent_name: agent.name,
          idle_duration: agent.idle_duration
        }
      );
    }
  });
}

/**
 * Monitor safety scores for concerning trends
 * @param {Array} telemetry - Array of telemetry events
 */
export function monitorSafetyScores(telemetry) {
  if (!telemetry || !Array.isArray(telemetry)) return;
  
  // Get recent events (last 10)
  const recentEvents = telemetry.slice(-10);
  
  // Count low safety scores
  const lowScoreCount = recentEvents.filter(e => 
    e.safety_score && e.safety_score < 50
  ).length;
  
  if (lowScoreCount >= 3) {
    alertStore.addAlert(
      `Safety concern: ${lowScoreCount} out of last 10 events had low safety scores`,
      AlertSeverity.HIGH,
      {
        low_score_count: lowScoreCount,
        total_checked: recentEvents.length
      }
    );
  }
}

/**
 * Monitor for dependency resolution issues
 * @param {Array} batches - Array of batch objects
 */
export function monitorDependencyIssues(batches) {
  if (!batches || !Array.isArray(batches)) return;
  
  batches.forEach(batch => {
    if (batch.depends_on && batch.status === "Blocked") {
      const parentBatch = batches.find(b => b.id === batch.depends_on);
      
      if (!parentBatch) {
        alertStore.addAlert(
          `Batch ${batch.id} depends on missing batch ${batch.depends_on}`,
          AlertSeverity.CRITICAL,
          {
            batch_id: batch.id,
            missing_dependency: batch.depends_on
          }
        );
      } else if (parentBatch.status === "Failed") {
        alertStore.addAlert(
          `Batch ${batch.id} is blocked due to failed dependency ${parentBatch.id}`,
          AlertSeverity.HIGH,
          {
            batch_id: batch.id,
            failed_dependency: parentBatch.id
          }
        );
      }
    }
  });
}

/**
 * Main monitoring function - runs all checks
 * @param {Object} state - Application state with plans, batches, agents, telemetry
 */
export function runAllMonitors(state) {
  if (!state) return;
  
  try {
    if (state.plans) {
      monitorStalledPlans(state.plans);
    }
    
    if (state.batches) {
      monitorBatchFailures(state.batches);
      monitorDependencyIssues(state.batches);
    }
    
    if (state.agents) {
      monitorAgentHealth(state.agents);
    }
    
    if (state.telemetry) {
      monitorSafetyScores(state.telemetry);
    }
  } catch (error) {
    console.error('Error running monitors:', error);
  }
}

/**
 * Start auto-monitoring with specified interval
 * @param {Object} getState - Function that returns current application state
 * @param {number} intervalMs - Monitoring interval in milliseconds
 * @returns {number} Interval ID for cleanup
 */
export function startAutoMonitoring(getState, intervalMs = 30000) {
  console.log(`Starting auto-monitoring (interval: ${intervalMs}ms)`);
  
  return setInterval(() => {
    const state = getState();
    runAllMonitors(state);
  }, intervalMs);
}

/**
 * Stop auto-monitoring
 * @param {number} intervalId - Interval ID from startAutoMonitoring
 */
export function stopAutoMonitoring(intervalId) {
  if (intervalId) {
    clearInterval(intervalId);
    console.log('Auto-monitoring stopped');
  }
}

// Export for direct usage in Vue components
export default {
  alertStore,
  alertStats,
  AlertSeverity,
  monitorStalledPlans,
  monitorBatchFailures,
  monitorAgentHealth,
  monitorSafetyScores,
  monitorDependencyIssues,
  runAllMonitors,
  startAutoMonitoring,
  stopAutoMonitoring
};

// Usage Example in Vue Component:
//
// <script setup>
// import { alertStore, startAutoMonitoring, stopAutoMonitoring } from './alertStore_automation.js';
// import { onMounted, onUnmounted } from 'vue';
//
// let monitoringInterval = null;
//
// onMounted(() => {
//   monitoringInterval = startAutoMonitoring(() => ({
//     plans: planStore.plans,
//     batches: batchStore.batches,
//     agents: agentStore.agents,
//     telemetry: telemetryStore.events
//   }), 30000); // Check every 30 seconds
// });
//
// onUnmounted(() => {
//   stopAutoMonitoring(monitoringInterval);
// });
// </script>

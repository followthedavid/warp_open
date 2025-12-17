import { watch } from 'vue'
import { writeTextFile } from '@tauri-apps/api/fs'

let testModeEnabled = false

export function enableTestMode() {
  testModeEnabled = true
  console.log('[TEST_MODE] Enabled')
  // Test mode is now simplified - just log the status
  // State tracking can be added back later if needed with the unified system
}

// Auto-enable if TEST_MODE env var is set
if (typeof window !== 'undefined' && (window as any).__WARP_TEST_MODE) {
  enableTestMode()
}

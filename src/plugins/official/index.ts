/**
 * Official Plugins Index
 *
 * These plugins are maintained by the Warp_Open team and serve as
 * reference implementations for Plugin API v2.
 */

export { GitInsightsPlugin } from './GitInsightsPlugin'
export { CommandLinterPlugin } from './CommandLinterPlugin'
export { SessionAnnotatorPlugin } from './SessionAnnotatorPlugin'

// Re-export for convenience
import { GitInsightsPlugin } from './GitInsightsPlugin'
import { CommandLinterPlugin } from './CommandLinterPlugin'
import { SessionAnnotatorPlugin } from './SessionAnnotatorPlugin'

export const OfficialPlugins = [
  GitInsightsPlugin,
  CommandLinterPlugin,
  SessionAnnotatorPlugin,
]

export default OfficialPlugins

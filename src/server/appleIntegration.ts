/**
 * Apple Ecosystem Integration
 * Seamless access from iPhone, iPad, Apple Watch, HomePod, Apple TV
 *
 * Integration Points:
 * ┌────────────────────────────────────────────────────────────────┐
 * │                      APPLE ECOSYSTEM                          │
 * │                                                                │
 * │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
 * │  │  iPhone  │  │   iPad   │  │  Watch   │  │   Mac    │       │
 * │  │ Shortcuts│  │ Shortcuts│  │   Siri   │  │ Terminal │       │
 * │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘       │
 * │       │             │             │             │              │
 * │       └─────────────┴──────┬──────┴─────────────┘              │
 * │                            │                                   │
 * │                    ┌───────▼───────┐                          │
 * │                    │  Siri Intent  │                          │
 * │                    │   Handler     │                          │
 * │                    └───────┬───────┘                          │
 * │                            │                                   │
 * │  ┌──────────┐      ┌───────▼───────┐      ┌──────────┐       │
 * │  │  HomePod │──────│   Warp API    │──────│ Apple TV │       │
 * │  └──────────┘      └───────────────┘      └──────────┘       │
 * └────────────────────────────────────────────────────────────────┘
 *
 * Features:
 * - Siri voice commands
 * - Apple Shortcuts automation
 * - Universal Links
 * - Handoff between devices
 * - Apple Watch complications
 * - HomePod voice queries
 * - Apple TV dashboard
 */

// ============================================================================
// TYPES
// ============================================================================

export interface AppleShortcut {
  identifier: string;
  title: string;
  description: string;
  icon: ShortcutIcon;
  parameters: ShortcutParameter[];
  outputType: 'text' | 'data' | 'void';
}

export interface ShortcutIcon {
  symbol: string;  // SF Symbol name
  color: string;   // Hex color
}

export interface ShortcutParameter {
  name: string;
  type: 'text' | 'number' | 'boolean' | 'enum' | 'file';
  required: boolean;
  defaultValue?: unknown;
  placeholder?: string;
  enumValues?: string[];
}

export interface SiriIntent {
  intentType: string;
  title: string;
  suggestedInvocationPhrase: string;
  parameters: Record<string, unknown>;
}

export interface WatchComplication {
  family: 'circular' | 'rectangular' | 'graphic';
  type: 'gauge' | 'text' | 'icon';
  data: ComplicationData;
}

export interface ComplicationData {
  title?: string;
  value?: string | number;
  icon?: string;
  gauge?: number;  // 0-1
  tint?: string;
}

export interface HomePodResponse {
  speech: string;
  displayText?: string;
  shouldEndSession: boolean;
  followUp?: string;
}

export interface AppleTVDashboard {
  title: string;
  sections: DashboardSection[];
  focusedItem?: string;
}

export interface DashboardSection {
  title: string;
  items: DashboardItem[];
}

export interface DashboardItem {
  id: string;
  title: string;
  subtitle?: string;
  icon?: string;
  status?: 'success' | 'warning' | 'error' | 'pending';
  action?: string;
}

// ============================================================================
// SHORTCUTS DEFINITIONS
// ============================================================================

export const SHORTCUTS: AppleShortcut[] = [
  {
    identifier: 'com.warpopen.ask',
    title: 'Ask Warp',
    description: 'Ask the AI assistant anything',
    icon: { symbol: 'bubble.left.and.bubble.right', color: '#007AFF' },
    parameters: [
      {
        name: 'question',
        type: 'text',
        required: true,
        placeholder: 'What would you like to know?'
      }
    ],
    outputType: 'text'
  },
  {
    identifier: 'com.warpopen.command',
    title: 'Run Command',
    description: 'Execute a terminal command',
    icon: { symbol: 'terminal', color: '#30D158' },
    parameters: [
      {
        name: 'command',
        type: 'text',
        required: true,
        placeholder: 'Enter command...'
      }
    ],
    outputType: 'text'
  },
  {
    identifier: 'com.warpopen.status',
    title: 'Warp Status',
    description: 'Check terminal and AI status',
    icon: { symbol: 'checkmark.circle', color: '#5856D6' },
    parameters: [],
    outputType: 'text'
  },
  {
    identifier: 'com.warpopen.approvals',
    title: 'Pending Approvals',
    description: 'Check for items needing your approval',
    icon: { symbol: 'exclamationmark.triangle', color: '#FF9500' },
    parameters: [],
    outputType: 'text'
  },
  {
    identifier: 'com.warpopen.approve',
    title: 'Approve Action',
    description: 'Approve a pending action by ID',
    icon: { symbol: 'checkmark.seal', color: '#34C759' },
    parameters: [
      {
        name: 'approvalId',
        type: 'text',
        required: true,
        placeholder: 'Approval ID'
      },
      {
        name: 'response',
        type: 'enum',
        required: true,
        enumValues: ['approve', 'reject', 'modify']
      }
    ],
    outputType: 'text'
  },
  {
    identifier: 'com.warpopen.pause',
    title: 'Pause AI Loop',
    description: 'Pause the self-improvement loop',
    icon: { symbol: 'pause.circle', color: '#FF3B30' },
    parameters: [],
    outputType: 'text'
  },
  {
    identifier: 'com.warpopen.resume',
    title: 'Resume AI Loop',
    description: 'Resume the self-improvement loop',
    icon: { symbol: 'play.circle', color: '#34C759' },
    parameters: [],
    outputType: 'text'
  },
  {
    identifier: 'com.warpopen.deploy',
    title: 'Deploy to Production',
    description: 'Promote staging changes to production',
    icon: { symbol: 'arrow.up.circle', color: '#007AFF' },
    parameters: [],
    outputType: 'text'
  }
];

// ============================================================================
// SIRI INTENTS
// ============================================================================

export const SIRI_INTENTS: SiriIntent[] = [
  {
    intentType: 'AskWarpIntent',
    title: 'Ask Warp',
    suggestedInvocationPhrase: 'Ask Warp',
    parameters: { question: '' }
  },
  {
    intentType: 'CheckStatusIntent',
    title: 'Check Warp Status',
    suggestedInvocationPhrase: 'Check Warp status',
    parameters: {}
  },
  {
    intentType: 'CheckApprovalsIntent',
    title: 'Check Approvals',
    suggestedInvocationPhrase: 'Any Warp approvals',
    parameters: {}
  },
  {
    intentType: 'PauseWarpIntent',
    title: 'Pause Warp',
    suggestedInvocationPhrase: 'Pause Warp',
    parameters: {}
  },
  {
    intentType: 'ResumeWarpIntent',
    title: 'Resume Warp',
    suggestedInvocationPhrase: 'Resume Warp',
    parameters: {}
  }
];

// ============================================================================
// INTENT HANDLERS
// ============================================================================

interface IntentContext {
  apiUrl: string;
  authToken: string;
}

async function callAPI(ctx: IntentContext, endpoint: string, method = 'GET', body?: unknown): Promise<unknown> {
  const response = await fetch(`${ctx.apiUrl}${endpoint}`, {
    method,
    headers: {
      'Authorization': `Bearer ${ctx.authToken}`,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });

  return response.json();
}

export async function handleAskIntent(ctx: IntentContext, question: string): Promise<HomePodResponse> {
  try {
    const result = await callAPI(ctx, '/api/query', 'POST', { query: question }) as { response: string };

    return {
      speech: result.response,
      displayText: result.response,
      shouldEndSession: true
    };
  } catch {
    return {
      speech: "I couldn't connect to Warp. Please check that your Mac is online.",
      shouldEndSession: true
    };
  }
}

export async function handleStatusIntent(ctx: IntentContext): Promise<HomePodResponse> {
  try {
    const status = await callAPI(ctx, '/api/status') as {
      status: string;
      pendingApprovals: number;
      completedCycles?: number;
    };

    let speech = `Warp is ${status.status}. `;

    if (status.pendingApprovals > 0) {
      speech += `You have ${status.pendingApprovals} pending approval${status.pendingApprovals > 1 ? 's' : ''}. `;
    }

    if (status.completedCycles) {
      speech += `${status.completedCycles} improvement cycles completed today.`;
    }

    return {
      speech,
      displayText: speech,
      shouldEndSession: true
    };
  } catch {
    return {
      speech: "I couldn't connect to Warp.",
      shouldEndSession: true
    };
  }
}

export async function handleApprovalsIntent(ctx: IntentContext): Promise<HomePodResponse> {
  try {
    const result = await callAPI(ctx, '/api/approvals') as { approvals: Array<{ title: string; priority: string }> };

    if (result.approvals.length === 0) {
      return {
        speech: "No pending approvals. Everything is running smoothly.",
        shouldEndSession: true
      };
    }

    const count = result.approvals.length;
    const highPriority = result.approvals.filter(a => a.priority === 'high' || a.priority === 'critical');

    let speech = `You have ${count} pending approval${count > 1 ? 's' : ''}. `;

    if (highPriority.length > 0) {
      speech += `${highPriority.length} ${highPriority.length > 1 ? 'are' : 'is'} high priority. `;
      speech += `The first one is: ${result.approvals[0].title}. `;
    }

    speech += "Would you like me to read them?";

    return {
      speech,
      displayText: speech,
      shouldEndSession: false,
      followUp: 'readApprovals'
    };
  } catch {
    return {
      speech: "I couldn't check for approvals.",
      shouldEndSession: true
    };
  }
}

export async function handleApproveIntent(
  ctx: IntentContext,
  approvalId: string,
  response: string
): Promise<HomePodResponse> {
  try {
    await callAPI(ctx, '/api/approve', 'POST', { approvalId, response });

    const responseText = response === 'approve' ? 'approved' :
                        response === 'reject' ? 'rejected' : 'marked for modification';

    return {
      speech: `Action ${responseText}. The system will continue.`,
      shouldEndSession: true
    };
  } catch {
    return {
      speech: "I couldn't process that approval. Please try again.",
      shouldEndSession: true
    };
  }
}

export async function handlePauseIntent(ctx: IntentContext): Promise<HomePodResponse> {
  try {
    await callAPI(ctx, '/api/command', 'POST', { command: '__pause__' });

    return {
      speech: "Warp improvement loop paused. Say 'Resume Warp' when you're ready to continue.",
      shouldEndSession: true
    };
  } catch {
    return {
      speech: "I couldn't pause Warp.",
      shouldEndSession: true
    };
  }
}

export async function handleResumeIntent(ctx: IntentContext): Promise<HomePodResponse> {
  try {
    await callAPI(ctx, '/api/command', 'POST', { command: '__resume__' });

    return {
      speech: "Warp improvement loop resumed. I'll continue working on improvements.",
      shouldEndSession: true
    };
  } catch {
    return {
      speech: "I couldn't resume Warp.",
      shouldEndSession: true
    };
  }
}

// ============================================================================
// WATCH COMPLICATIONS
// ============================================================================

export function generateWatchComplication(status: {
  isRunning: boolean;
  pendingApprovals: number;
  completedCycles: number;
  currentTask?: string;
}): WatchComplication[] {
  return [
    // Circular gauge showing progress
    {
      family: 'circular',
      type: 'gauge',
      data: {
        gauge: status.isRunning ? 0.7 : 0,
        icon: status.isRunning ? 'play.fill' : 'pause.fill',
        tint: status.pendingApprovals > 0 ? '#FF9500' : '#34C759'
      }
    },

    // Rectangular text
    {
      family: 'rectangular',
      type: 'text',
      data: {
        title: 'Warp',
        value: status.pendingApprovals > 0
          ? `${status.pendingApprovals} approval${status.pendingApprovals > 1 ? 's' : ''}`
          : status.isRunning
            ? 'Running'
            : 'Paused',
        icon: status.pendingApprovals > 0 ? 'exclamationmark.triangle' : 'checkmark.circle'
      }
    },

    // Graphic corner
    {
      family: 'graphic',
      type: 'icon',
      data: {
        icon: status.pendingApprovals > 0 ? 'exclamationmark.triangle.fill' : 'terminal.fill',
        tint: status.pendingApprovals > 0 ? '#FF9500' : '#007AFF'
      }
    }
  ];
}

// ============================================================================
// APPLE TV DASHBOARD
// ============================================================================

export function generateTVDashboard(status: {
  isRunning: boolean;
  currentTask?: { title: string; description: string };
  pendingApprovals: Array<{ id: string; title: string; priority: string }>;
  recentChanges: Array<{ path: string; type: string }>;
  completedCycles: number;
  failedCycles: number;
}): AppleTVDashboard {
  const sections: DashboardSection[] = [];

  // Status section
  sections.push({
    title: 'Status',
    items: [
      {
        id: 'status',
        title: status.isRunning ? 'Running' : 'Paused',
        subtitle: status.currentTask?.title || 'Idle',
        icon: status.isRunning ? 'play.fill' : 'pause.fill',
        status: status.isRunning ? 'success' : 'pending'
      },
      {
        id: 'cycles',
        title: `${status.completedCycles} Completed`,
        subtitle: `${status.failedCycles} failed`,
        icon: 'chart.bar.fill',
        status: status.failedCycles > status.completedCycles * 0.1 ? 'warning' : 'success'
      }
    ]
  });

  // Pending Approvals
  if (status.pendingApprovals.length > 0) {
    sections.push({
      title: 'Pending Approvals',
      items: status.pendingApprovals.map(a => ({
        id: a.id,
        title: a.title,
        subtitle: a.priority,
        icon: 'exclamationmark.triangle.fill',
        status: a.priority === 'critical' ? 'error' : 'warning' as const,
        action: `approve:${a.id}`
      }))
    });
  }

  // Recent Changes
  if (status.recentChanges.length > 0) {
    sections.push({
      title: 'Recent Changes',
      items: status.recentChanges.slice(0, 5).map((c, i) => ({
        id: `change-${i}`,
        title: c.path,
        subtitle: c.type,
        icon: c.type === 'create' ? 'plus.circle' :
              c.type === 'delete' ? 'minus.circle' : 'pencil.circle',
        status: 'success' as const
      }))
    });
  }

  return {
    title: 'Warp Control Center',
    sections,
    focusedItem: status.pendingApprovals.length > 0 ? status.pendingApprovals[0].id : 'status'
  };
}

// ============================================================================
// HANDOFF
// ============================================================================

export interface HandoffActivity {
  activityType: string;
  title: string;
  userInfo: Record<string, unknown>;
  webpageURL?: string;
}

export function createHandoffActivity(context: {
  type: 'viewing_approval' | 'editing_file' | 'running_command';
  id?: string;
  data?: Record<string, unknown>;
}): HandoffActivity {
  switch (context.type) {
    case 'viewing_approval':
      return {
        activityType: 'com.warpopen.viewApproval',
        title: 'Viewing Approval',
        userInfo: { approvalId: context.id },
        webpageURL: `https://warp.local/approve/${context.id}`
      };

    case 'editing_file':
      return {
        activityType: 'com.warpopen.editFile',
        title: 'Editing File',
        userInfo: { filePath: context.id },
        webpageURL: `https://warp.local/edit/${encodeURIComponent(context.id || '')}`
      };

    case 'running_command':
      return {
        activityType: 'com.warpopen.runCommand',
        title: 'Running Command',
        userInfo: context.data || {},
        webpageURL: 'https://warp.local/terminal'
      };

    default:
      return {
        activityType: 'com.warpopen.main',
        title: 'Warp Open',
        userInfo: {}
      };
  }
}

// ============================================================================
// HOMEKIT INTEGRATION
// ============================================================================

/**
 * HomeKit Integration via Homebridge
 *
 * Devices exposed:
 * - Switch: "Warp AI" (on/off for running state)
 * - Motion Sensor: "Warp Approvals" (triggers when approvals pending)
 * - Light: "Warp Status" (brightness = progress, color = status)
 *
 * Automations possible:
 * - Turn on desk lamp when approval needed
 * - Flash lights on error
 * - Pause AI when leaving home
 * - Resume AI when arriving home
 */

export interface HomeKitAccessory {
  name: string;
  type: 'switch' | 'motionSensor' | 'lightbulb' | 'contactSensor' | 'speaker';
  uuid: string;
  characteristics: HomeKitCharacteristic[];
}

export interface HomeKitCharacteristic {
  type: string;
  value: unknown;
  props?: {
    minValue?: number;
    maxValue?: number;
    minStep?: number;
  };
}

export interface HomeKitBridgeConfig {
  bridgeName: string;
  bridgeUsername: string;  // MAC-like format: XX:XX:XX:XX:XX:XX
  bridgePort: number;
  bridgePin: string;       // XXX-XX-XXX format
  accessories: HomeKitAccessory[];
}

// Default HomeKit configuration
export const HOMEKIT_CONFIG: HomeKitBridgeConfig = {
  bridgeName: 'Warp Open',
  bridgeUsername: 'CC:22:3D:E3:CE:30',
  bridgePort: 47128,
  bridgePin: '031-45-154',
  accessories: [
    {
      name: 'Warp AI',
      type: 'switch',
      uuid: 'warp-ai-switch',
      characteristics: [
        { type: 'On', value: false }
      ]
    },
    {
      name: 'Warp Approvals',
      type: 'motionSensor',
      uuid: 'warp-approvals-sensor',
      characteristics: [
        { type: 'MotionDetected', value: false }
      ]
    },
    {
      name: 'Warp Status Light',
      type: 'lightbulb',
      uuid: 'warp-status-light',
      characteristics: [
        { type: 'On', value: true },
        { type: 'Brightness', value: 0, props: { minValue: 0, maxValue: 100, minStep: 1 } },
        { type: 'Hue', value: 120, props: { minValue: 0, maxValue: 360, minStep: 1 } },  // Green
        { type: 'Saturation', value: 100, props: { minValue: 0, maxValue: 100, minStep: 1 } }
      ]
    },
    {
      name: 'Warp Running',
      type: 'contactSensor',
      uuid: 'warp-running-sensor',
      characteristics: [
        { type: 'ContactSensorState', value: 0 }  // 0 = closed (not running), 1 = open (running)
      ]
    }
  ]
};

// Status colors in HSL
const STATUS_COLORS = {
  running: { hue: 120, saturation: 100 },    // Green
  paused: { hue: 45, saturation: 100 },      // Yellow/Orange
  waiting: { hue: 30, saturation: 100 },     // Orange
  error: { hue: 0, saturation: 100 },        // Red
  idle: { hue: 210, saturation: 50 }         // Blue-gray
};

/**
 * Generate HomeKit state from Warp status
 */
export function generateHomeKitState(status: {
  isRunning: boolean;
  isPaused: boolean;
  hasApprovals: boolean;
  cycleProgress: number;  // 0-100
  errorState: boolean;
}): Record<string, unknown> {
  let statusColor = STATUS_COLORS.idle;

  if (status.errorState) {
    statusColor = STATUS_COLORS.error;
  } else if (status.hasApprovals) {
    statusColor = STATUS_COLORS.waiting;
  } else if (status.isPaused) {
    statusColor = STATUS_COLORS.paused;
  } else if (status.isRunning) {
    statusColor = STATUS_COLORS.running;
  }

  return {
    'warp-ai-switch': {
      On: status.isRunning && !status.isPaused
    },
    'warp-approvals-sensor': {
      MotionDetected: status.hasApprovals
    },
    'warp-status-light': {
      On: true,
      Brightness: status.isRunning ? Math.max(10, status.cycleProgress) : 5,
      Hue: statusColor.hue,
      Saturation: statusColor.saturation
    },
    'warp-running-sensor': {
      ContactSensorState: status.isRunning ? 1 : 0  // Open when running
    }
  };
}

/**
 * Handle HomeKit commands
 */
export async function handleHomeKitCommand(
  accessoryId: string,
  characteristic: string,
  value: unknown,
  ctx: { apiUrl: string; authToken: string }
): Promise<boolean> {
  try {
    if (accessoryId === 'warp-ai-switch' && characteristic === 'On') {
      const command = value ? '__resume__' : '__pause__';
      await fetch(`${ctx.apiUrl}/api/command`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${ctx.authToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ command })
      });
      return true;
    }

    return false;
  } catch {
    return false;
  }
}

/**
 * Generate Homebridge config.json snippet
 */
export function generateHomebridgeConfig(serverUrl: string, authToken: string): object {
  return {
    platform: 'HttpWebHooks',
    name: 'Warp Open',
    webhook_port: 51828,
    sensors: [
      {
        id: 'warp-approvals',
        name: 'Warp Approvals',
        type: 'motion',
        autoRelease: false
      },
      {
        id: 'warp-running',
        name: 'Warp Running',
        type: 'contact'
      }
    ],
    switches: [
      {
        id: 'warp-ai',
        name: 'Warp AI',
        on_url: `${serverUrl}/api/command`,
        on_method: 'POST',
        on_body: '{"command":"__resume__"}',
        on_headers: `{"Authorization":"Bearer ${authToken}","Content-Type":"application/json"}`,
        off_url: `${serverUrl}/api/command`,
        off_method: 'POST',
        off_body: '{"command":"__pause__"}',
        off_headers: `{"Authorization":"Bearer ${authToken}","Content-Type":"application/json"}`
      }
    ],
    lights: [
      {
        id: 'warp-status',
        name: 'Warp Status Light'
      }
    ]
  };
}

/**
 * HomeKit automation suggestions
 */
export const HOMEKIT_AUTOMATIONS = [
  {
    name: 'Alert on Approval Needed',
    description: 'Flash lights when an approval is needed',
    trigger: 'When Warp Approvals detects motion',
    actions: [
      'Flash office lights 3 times',
      'Turn on notification light (red)'
    ]
  },
  {
    name: 'Status on Desk',
    description: 'Show AI status via desk lamp color',
    trigger: 'When Warp Status Light changes',
    actions: [
      'Set desk lamp to match Warp Status Light color'
    ]
  },
  {
    name: 'Pause When Away',
    description: 'Pause AI when you leave home',
    trigger: 'When last person leaves home',
    actions: [
      'Turn off Warp AI switch'
    ]
  },
  {
    name: 'Resume When Home',
    description: 'Resume AI when you arrive',
    trigger: 'When first person arrives home',
    actions: [
      'Turn on Warp AI switch'
    ]
  },
  {
    name: 'Night Mode',
    description: 'Dim status light at night',
    trigger: 'At 10:00 PM',
    actions: [
      'Set Warp Status Light brightness to 10%'
    ]
  },
  {
    name: 'Good Morning Status',
    description: 'Announce status in the morning',
    trigger: 'When "Good Morning" scene runs',
    actions: [
      'If Warp Approvals has motion: Announce "You have pending Warp approvals"'
    ]
  }
];

// ============================================================================
// EXPORTS
// ============================================================================

export default {
  shortcuts: SHORTCUTS,
  siriIntents: SIRI_INTENTS,

  // Intent handlers
  handleAskIntent,
  handleStatusIntent,
  handleApprovalsIntent,
  handleApproveIntent,
  handlePauseIntent,
  handleResumeIntent,

  // Watch
  generateWatchComplication,

  // TV
  generateTVDashboard,

  // Handoff
  createHandoffActivity,

  // HomeKit
  HOMEKIT_CONFIG,
  generateHomeKitState,
  handleHomeKitCommand,
  generateHomebridgeConfig,
  HOMEKIT_AUTOMATIONS
};

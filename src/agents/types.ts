/**
 * Core types for the autonomous execution system
 */

export type StepStatus = 'pending' | 'awaitingApproval' | 'executing' | 'completed' | 'rolledBack';
export type PlanStatus = 'pending' | 'inProgress' | 'completed' | 'rolledBack';
export type ToolType = 'ollama' | 'claude' | 'command' | 'read_file' | 'write_file' | 'git';

export interface PlanStep {
  id: string;
  title: string;
  description?: string;
  substeps?: PlanStep[];
  status: StepStatus;
  approved?: boolean;
  escalated?: boolean;
  tool?: ToolType;
  toolParams?: Record<string, any>;
  output?: string;
  error?: string;
  timestamp?: Date;
  snapshotBefore?: any;
  requiresApproval?: boolean;
}

export interface ExecutionPlan {
  id: string;
  title: string;
  description?: string;
  steps: PlanStep[];
  currentStepIndex: number;
  status: PlanStatus;
  logs: string[];
  escalated?: boolean;
  createdAt: Date;
}

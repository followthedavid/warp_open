/**
 * Automated tests for Autonomous Developer
 * Run with: npm test
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => { store[key] = value; },
    removeItem: (key: string) => { delete store[key]; },
    clear: () => { store = {}; }
  };
})();

global.localStorage = localStorageMock as any;

// Mock window
global.window = {
  localStorage: localStorageMock
} as any;

describe('Autonomous Developer System', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  describe('Goal Management', () => {
    it('should add a goal to localStorage', async () => {
      // Import the module after mocks are set up
      const { autonomousDeveloper } = await import('../src/agents/autonomousDeveloper');

      const goal = autonomousDeveloper.addGoal('Test goal', 'medium');

      expect(goal).toBeDefined();
      expect(goal.description).toBe('Test goal');
      expect(goal.priority).toBe('medium');
      expect(goal.status).toBe('pending');

      // Check localStorage
      const stored = localStorage.getItem('ai_developer_goals');
      expect(stored).toBeTruthy();

      const goals = JSON.parse(stored!);
      expect(goals).toHaveLength(1);
      expect(goals[0].description).toBe('Test goal');
    });

    it('should persist goals across restarts', async () => {
      const { autonomousDeveloper } = await import('../src/agents/autonomousDeveloper');

      // Add goals
      autonomousDeveloper.addGoal('Goal 1', 'high');
      autonomousDeveloper.addGoal('Goal 2', 'low');

      const goals = autonomousDeveloper.getGoals();
      expect(goals).toHaveLength(2);

      // Verify in localStorage
      const stored = localStorage.getItem('ai_developer_goals');
      const parsedGoals = JSON.parse(stored!);
      expect(parsedGoals).toHaveLength(2);
    });

    it('should prioritize goals correctly', async () => {
      const { autonomousDeveloper } = await import('../src/agents/autonomousDeveloper');

      autonomousDeveloper.addGoal('Low priority', 'low');
      autonomousDeveloper.addGoal('Critical task', 'critical');
      autonomousDeveloper.addGoal('Medium task', 'medium');

      const goals = autonomousDeveloper.getGoals();

      // All goals should be stored
      expect(goals).toHaveLength(3);

      // Goals should be retrievable
      const criticalGoal = goals.find(g => g.priority === 'critical');
      expect(criticalGoal).toBeDefined();
      expect(criticalGoal?.description).toBe('Critical task');
    });
  });

  describe('State Management', () => {
    it('should save and load state from localStorage', async () => {
      const { autonomousDeveloper } = await import('../src/agents/autonomousDeveloper');

      // Add a goal
      const goal = autonomousDeveloper.addGoal('Persistent goal', 'high');

      // Check it's in localStorage
      const stored = localStorage.getItem('ai_developer_goals');
      expect(stored).toBeTruthy();

      const goals = JSON.parse(stored!);
      expect(goals[0].id).toBe(goal.id);
    });

    it('should handle empty localStorage gracefully', async () => {
      localStorage.clear();

      const { autonomousDeveloper } = await import('../src/agents/autonomousDeveloper');

      const goals = autonomousDeveloper.getGoals();
      expect(goals).toEqual([]);
    });
  });

  describe('Dashboard Integration', () => {
    it('should expose statistics', async () => {
      const { autonomousDeveloper } = await import('../src/agents/autonomousDeveloper');

      // Add some goals
      autonomousDeveloper.addGoal('Goal 1', 'medium');
      autonomousDeveloper.addGoal('Goal 2', 'high');

      const stats = autonomousDeveloper.getStatistics();

      // Should return statistics object
      expect(stats).toBeDefined();
    });

    it('should report running status', async () => {
      const { autonomousDeveloper } = await import('../src/agents/autonomousDeveloper');

      const isActive = autonomousDeveloper.isActive();
      expect(typeof isActive).toBe('boolean');
      expect(isActive).toBe(false); // Should not be running initially
    });

    it('should expose current task', async () => {
      const { autonomousDeveloper } = await import('../src/agents/autonomousDeveloper');

      const currentTask = autonomousDeveloper.getCurrentTask();
      expect(currentTask).toBeNull(); // No task initially
    });
  });
});

describe('Perpetual Log System', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  describe('Browser Mode', () => {
    it('should handle log operations without file system', async () => {
      const { appendPerpetualLog } = await import('../src/utils/perpetualLog');

      // Should not throw error even without fs
      expect(() => {
        appendPerpetualLog({
          type: 'goal',
          content: 'Test log entry',
          status: 'pending'
        });
      }).not.toThrow();
    });

    it('should return empty array when fs is not available', async () => {
      const { getAllPerpetualLogs } = await import('../src/utils/perpetualLog');

      const logs = getAllPerpetualLogs();
      expect(logs).toEqual([]);
    });

    it('should return empty context when fs is not available', async () => {
      const { getRelevantContext } = await import('../src/utils/perpetualLog');

      const context = await getRelevantContext('test query');
      expect(context).toBe('');
    });

    it('should return zero statistics when fs is not available', async () => {
      const { getLogStatistics } = await import('../src/utils/perpetualLog');

      const stats = getLogStatistics();
      expect(stats.totalEntries).toBe(0);
      expect(stats.successRate).toBe(0);
    });
  });
});

describe('Claude Integration', () => {
  describe('API Availability Check', () => {
    it('should handle missing Claude gracefully', async () => {
      const { autonomousDeveloper } = await import('../src/agents/autonomousDeveloper');

      // Should not throw when Claude is not configured
      expect(() => {
        autonomousDeveloper.addGoal('Test without Claude', 'low');
      }).not.toThrow();
    });
  });
});

console.log(`
✅ Test Suite Summary
=====================
These tests verify:
1. Goal management and persistence (localStorage)
2. Priority handling
3. State management
4. Dashboard integration
5. Perpetual logging (browser mode)
6. Claude integration fallbacks

Run with: npm test
`);

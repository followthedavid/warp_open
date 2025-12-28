/**
 * Smart Command Router - Makes small LLMs work reliably
 *
 * Strategy:
 * 1. Rule-based fast paths (bypass LLM entirely)
 * 2. Pattern matching with confidence scoring
 * 3. Output validation and auto-correction
 * 4. Learning from successful executions
 * 5. Fallback to LLM only when necessary
 */

import { ref } from 'vue';

// ============================================================================
// RULE-BASED FAST PATHS - Bypass LLM entirely for common commands
// ============================================================================

interface CommandRule {
  patterns: RegExp[];
  command: string | ((match: RegExpMatchArray, input: string) => string);
  confidence: number;
  description: string;
  category: 'file' | 'system' | 'git' | 'npm' | 'docker' | 'network' | 'process';
  safe: boolean; // Can auto-execute without confirmation
}

const COMMAND_RULES: CommandRule[] = [
  // === FILE OPERATIONS ===
  {
    patterns: [/^(list|show|ls|dir)\s*(files?|folders?|directories?)?$/i, /^what('s| is) (in )?(this|the|current) (dir|directory|folder)$/i],
    command: 'ls -la',
    confidence: 1.0,
    description: 'List files in current directory',
    category: 'file',
    safe: true
  },
  {
    patterns: [/^(list|show|ls)\s*(files?|folders?)?\s*(in|at|from)\s+(.+)$/i],
    command: (m) => `ls -la "${m[4]}"`,
    confidence: 0.95,
    description: 'List files in specific directory',
    category: 'file',
    safe: true
  },
  {
    patterns: [/^(pwd|where am i|current (dir|directory|path|folder)|what('s| is) (the )?(current )?(dir|directory|path))$/i],
    command: 'pwd',
    confidence: 1.0,
    description: 'Show current directory',
    category: 'file',
    safe: true
  },
  {
    patterns: [/^(cat|show|read|view|display|print)\s+(.+)$/i],
    command: (m) => `cat "${m[2].trim()}"`,
    confidence: 0.9,
    description: 'Show file contents',
    category: 'file',
    safe: true
  },
  {
    patterns: [/^(find|search|look for)\s+(files?|folders?)?\s*(named|called|matching)?\s+(.+)$/i],
    command: (m) => `find . -name "*${m[4].trim()}*" 2>/dev/null | head -20`,
    confidence: 0.85,
    description: 'Find files by name',
    category: 'file',
    safe: true
  },
  {
    patterns: [/^(search|grep|find|look)\s+(for\s+)?["']?(.+?)["']?\s+(in|inside|within)\s+(.+)$/i],
    command: (m) => `grep -rn "${m[3]}" "${m[5].trim()}" 2>/dev/null | head -20`,
    confidence: 0.85,
    description: 'Search for text in files',
    category: 'file',
    safe: true
  },
  {
    patterns: [/^(make|create|mkdir)\s+(dir|directory|folder)\s+(.+)$/i],
    command: (m) => `mkdir -p "${m[3].trim()}"`,
    confidence: 0.95,
    description: 'Create directory',
    category: 'file',
    safe: false // Modifies filesystem
  },
  {
    patterns: [/^(touch|create)\s+(file\s+)?(.+)$/i],
    command: (m) => `touch "${m[3].trim()}"`,
    confidence: 0.9,
    description: 'Create empty file',
    category: 'file',
    safe: false
  },
  {
    patterns: [/^(disk|storage|space|df)\s*(usage|space|free)?$/i, /^how much (disk |storage )?(space|room)( (is )?(left|free|available))?$/i],
    command: 'df -h',
    confidence: 1.0,
    description: 'Show disk usage',
    category: 'system',
    safe: true
  },
  {
    patterns: [/^(file|folder|directory)\s*size\s*(of\s+)?(.+)$/i, /^how (big|large) is (.+)$/i],
    command: (m) => `du -sh "${(m[3] || m[2]).trim()}"`,
    confidence: 0.9,
    description: 'Show file/directory size',
    category: 'file',
    safe: true
  },
  {
    patterns: [/^(tree|show tree|directory tree)(\s+(.+))?$/i],
    command: (m) => m[3] ? `tree "${m[3].trim()}" -L 3 2>/dev/null || find "${m[3].trim()}" -type d | head -30` : 'tree -L 3 2>/dev/null || find . -type d | head -30',
    confidence: 0.9,
    description: 'Show directory tree',
    category: 'file',
    safe: true
  },

  // === SYSTEM INFO ===
  {
    patterns: [/^(date|time|what time|what('s| is) the (time|date))$/i],
    command: 'date',
    confidence: 1.0,
    description: 'Show current date/time',
    category: 'system',
    safe: true
  },
  {
    patterns: [/^(whoami|who am i|what('s| is) my (user|username))$/i],
    command: 'whoami',
    confidence: 1.0,
    description: 'Show current user',
    category: 'system',
    safe: true
  },
  {
    patterns: [/^(hostname|what('s| is) (this |the )?(machine|computer|host)(name)?)$/i],
    command: 'hostname',
    confidence: 1.0,
    description: 'Show hostname',
    category: 'system',
    safe: true
  },
  {
    patterns: [/^(uptime|how long|system uptime)$/i],
    command: 'uptime',
    confidence: 1.0,
    description: 'Show system uptime',
    category: 'system',
    safe: true
  },
  {
    patterns: [/^(memory|ram|mem)\s*(usage|info|status)?$/i, /^how much (memory|ram)( (is )?(used|free|available))?$/i],
    command: 'vm_stat 2>/dev/null || free -h 2>/dev/null || top -l 1 | head -10',
    confidence: 0.95,
    description: 'Show memory usage',
    category: 'system',
    safe: true
  },
  {
    patterns: [/^(cpu|processor)\s*(info|usage|status)?$/i],
    command: 'sysctl -n machdep.cpu.brand_string 2>/dev/null || cat /proc/cpuinfo 2>/dev/null | head -20 || echo "CPU info not available"',
    confidence: 0.9,
    description: 'Show CPU info',
    category: 'system',
    safe: true
  },
  {
    patterns: [/^(env|environment|env vars|environment variables)$/i],
    command: 'env | sort | head -30',
    confidence: 1.0,
    description: 'Show environment variables',
    category: 'system',
    safe: true
  },
  {
    patterns: [/^(os|system|uname)\s*(info|version)?$/i, /^what (os|system|operating system)( (am i|is this))?$/i],
    command: 'uname -a',
    confidence: 1.0,
    description: 'Show OS info',
    category: 'system',
    safe: true
  },

  // === PROCESS MANAGEMENT ===
  {
    patterns: [/^(ps|processes|running|what('s| is) running)$/i],
    command: 'ps aux | head -20',
    confidence: 1.0,
    description: 'Show running processes',
    category: 'process',
    safe: true
  },
  {
    patterns: [/^(top|htop|activity)$/i],
    command: 'top -l 1 | head -20 2>/dev/null || top -b -n 1 | head -20',
    confidence: 0.95,
    description: 'Show top processes',
    category: 'process',
    safe: true
  },
  {
    patterns: [/^(kill|stop)\s+(process\s+)?(\d+)$/i],
    command: (m) => `kill ${m[3]}`,
    confidence: 0.9,
    description: 'Kill process by PID',
    category: 'process',
    safe: false
  },
  {
    patterns: [/^(find|search|which|where)\s+(process|pid)\s+(.+)$/i, /^what('s| is) (using|running on)\s+(.+)$/i],
    command: (m) => `pgrep -fl "${m[3].trim()}" 2>/dev/null || ps aux | grep -i "${m[3].trim()}" | grep -v grep`,
    confidence: 0.85,
    description: 'Find process by name',
    category: 'process',
    safe: true
  },

  // === NETWORK ===
  {
    patterns: [/^(ip|my ip|ip address|what('s| is) my ip)$/i],
    command: 'ifconfig 2>/dev/null | grep "inet " | grep -v 127.0.0.1 || ip addr 2>/dev/null | grep "inet " | grep -v 127.0.0.1',
    confidence: 1.0,
    description: 'Show IP address',
    category: 'network',
    safe: true
  },
  {
    patterns: [/^(ping)\s+(.+)$/i],
    command: (m) => `ping -c 4 "${m[2].trim()}"`,
    confidence: 0.95,
    description: 'Ping host',
    category: 'network',
    safe: true
  },
  {
    patterns: [/^(ports|listening|what('s| is) listening|open ports)$/i],
    command: 'lsof -i -P -n | grep LISTEN | head -20 2>/dev/null || netstat -tlnp 2>/dev/null | head -20',
    confidence: 0.95,
    description: 'Show listening ports',
    category: 'network',
    safe: true
  },
  {
    patterns: [/^(curl|fetch|get|download)\s+(.+)$/i],
    command: (m) => `curl -sL "${m[2].trim()}" | head -100`,
    confidence: 0.85,
    description: 'Fetch URL',
    category: 'network',
    safe: true
  },

  // === GIT ===
  {
    patterns: [/^git\s+status$/i, /^(status|git status|what('s| is) changed|changes)$/i],
    command: 'git status',
    confidence: 1.0,
    description: 'Git status',
    category: 'git',
    safe: true
  },
  {
    patterns: [/^git\s+log$/i, /^(git )?(log|history|commits)$/i],
    command: 'git log --oneline -20',
    confidence: 1.0,
    description: 'Git log',
    category: 'git',
    safe: true
  },
  {
    patterns: [/^git\s+diff$/i, /^(git )?(diff|changes|what changed)$/i],
    command: 'git diff',
    confidence: 1.0,
    description: 'Git diff',
    category: 'git',
    safe: true
  },
  {
    patterns: [/^git\s+branch$/i, /^(git )?(branches|what branch|current branch)$/i],
    command: 'git branch -a',
    confidence: 1.0,
    description: 'Git branches',
    category: 'git',
    safe: true
  },
  {
    patterns: [/^git\s+remote$/i, /^(git )?(remotes?|origins?)$/i],
    command: 'git remote -v',
    confidence: 1.0,
    description: 'Git remotes',
    category: 'git',
    safe: true
  },
  {
    patterns: [/^git\s+stash\s+list$/i, /^(git )?(stash(es)?|stash list)$/i],
    command: 'git stash list',
    confidence: 1.0,
    description: 'Git stashes',
    category: 'git',
    safe: true
  },

  // === NPM/NODE ===
  {
    patterns: [/^npm\s+list$/i, /^(npm |node )?(packages|dependencies|deps)$/i],
    command: 'npm list --depth=0 2>/dev/null || cat package.json 2>/dev/null | head -50',
    confidence: 0.95,
    description: 'List npm packages',
    category: 'npm',
    safe: true
  },
  {
    patterns: [/^npm\s+run$/i, /^(npm )?(scripts|run scripts)$/i],
    command: 'npm run 2>/dev/null || cat package.json | grep -A 20 \'"scripts"\'',
    confidence: 0.95,
    description: 'List npm scripts',
    category: 'npm',
    safe: true
  },
  {
    patterns: [/^(node|npm)\s+(version|v|-v|--version)$/i],
    command: 'node -v && npm -v',
    confidence: 1.0,
    description: 'Node/npm version',
    category: 'npm',
    safe: true
  },
  {
    patterns: [/^npm\s+install$/i, /^(install|npm install|npm i)$/i],
    command: 'npm install',
    confidence: 0.95,
    description: 'Install npm dependencies',
    category: 'npm',
    safe: false
  },
  {
    patterns: [/^npm\s+test$/i, /^(test|run tests|npm test)$/i],
    command: 'npm test',
    confidence: 0.95,
    description: 'Run npm tests',
    category: 'npm',
    safe: false
  },
  {
    patterns: [/^npm\s+run\s+(.+)$/i],
    command: (m) => `npm run ${m[1].trim()}`,
    confidence: 0.9,
    description: 'Run npm script',
    category: 'npm',
    safe: false
  },

  // === DOCKER ===
  {
    patterns: [/^docker\s+ps$/i, /^(docker )?(containers|running containers)$/i],
    command: 'docker ps',
    confidence: 1.0,
    description: 'List Docker containers',
    category: 'docker',
    safe: true
  },
  {
    patterns: [/^docker\s+images$/i, /^(docker )?(images|docker images)$/i],
    command: 'docker images',
    confidence: 1.0,
    description: 'List Docker images',
    category: 'docker',
    safe: true
  },
  {
    patterns: [/^docker\s+logs\s+(.+)$/i],
    command: (m) => `docker logs --tail 50 "${m[1].trim()}"`,
    confidence: 0.9,
    description: 'Docker container logs',
    category: 'docker',
    safe: true
  },
];

// ============================================================================
// CONFIDENCE SCORING
// ============================================================================

export interface CommandMatch {
  command: string;
  confidence: number;
  description: string;
  category: string;
  safe: boolean;
  source: 'rule' | 'pattern' | 'llm';
}

// ============================================================================
// LEARNED PATTERNS - Grows over time
// ============================================================================

interface LearnedPattern {
  input: string;
  command: string;
  successCount: number;
  failCount: number;
  lastUsed: number;
}

const learnedPatterns = ref<Map<string, LearnedPattern>>(new Map());

// Load from localStorage
function loadLearnedPatterns() {
  try {
    const saved = localStorage.getItem('warp_learned_commands');
    if (saved) {
      const data = JSON.parse(saved) as LearnedPattern[];
      data.forEach(p => learnedPatterns.value.set(p.input.toLowerCase(), p));
    }
  } catch (e) {
    console.error('Failed to load learned patterns:', e);
  }
}

function saveLearnedPatterns() {
  try {
    const data = Array.from(learnedPatterns.value.values());
    localStorage.setItem('warp_learned_commands', JSON.stringify(data));
  } catch (e) {
    console.error('Failed to save learned patterns:', e);
  }
}

// Initialize
loadLearnedPatterns();

// ============================================================================
// MAIN ROUTER
// ============================================================================

export function useSmartCommands() {
  /**
   * Find the best command for an input, using rules first, then patterns, then LLM
   */
  function findCommand(input: string): CommandMatch | null {
    const normalizedInput = input.trim().toLowerCase();

    // 1. Check learned patterns first (highest priority for exact matches)
    const learned = learnedPatterns.value.get(normalizedInput);
    if (learned && learned.successCount > learned.failCount) {
      return {
        command: learned.command,
        confidence: Math.min(0.95, 0.7 + (learned.successCount * 0.05)),
        description: 'Learned from previous successful execution',
        category: 'learned',
        safe: false, // Always confirm learned commands
        source: 'pattern'
      };
    }

    // 2. Check rule-based fast paths
    for (const rule of COMMAND_RULES) {
      for (const pattern of rule.patterns) {
        const match = input.match(pattern);
        if (match) {
          const command = typeof rule.command === 'function'
            ? rule.command(match, input)
            : rule.command;
          return {
            command,
            confidence: rule.confidence,
            description: rule.description,
            category: rule.category,
            safe: rule.safe,
            source: 'rule'
          };
        }
      }
    }

    // 3. Fuzzy matching for near-misses
    const fuzzyMatch = findFuzzyMatch(normalizedInput);
    if (fuzzyMatch && fuzzyMatch.confidence > 0.7) {
      return fuzzyMatch;
    }

    // 4. Return null - caller should use LLM
    return null;
  }

  /**
   * Fuzzy matching for inputs that are close to rules
   */
  function findFuzzyMatch(input: string): CommandMatch | null {
    const words = input.split(/\s+/);
    let bestMatch: CommandMatch | null = null;
    let bestScore = 0;

    for (const rule of COMMAND_RULES) {
      // Score based on keyword overlap
      let score = 0;
      const ruleKeywords = rule.description.toLowerCase().split(/\s+/);

      for (const word of words) {
        if (ruleKeywords.some(k => k.includes(word) || word.includes(k))) {
          score += 1;
        }
      }

      // Normalize score
      const normalizedScore = score / Math.max(words.length, ruleKeywords.length);

      if (normalizedScore > bestScore && normalizedScore > 0.3) {
        bestScore = normalizedScore;
        // For fuzzy matches, use the static command or skip function-based ones
        const command = typeof rule.command === 'function'
          ? null // Skip function-based rules for fuzzy matching
          : rule.command;
        if (!command) continue;
        bestMatch = {
          command,
          confidence: normalizedScore * 0.8, // Cap at 0.8 for fuzzy
          description: rule.description,
          category: rule.category,
          safe: false, // Never auto-execute fuzzy matches
          source: 'rule'
        };
      }
    }

    return bestMatch;
  }

  /**
   * Record successful command execution for learning
   */
  function recordSuccess(input: string, command: string) {
    const key = input.trim().toLowerCase();
    const existing = learnedPatterns.value.get(key);

    if (existing) {
      existing.successCount++;
      existing.lastUsed = Date.now();
    } else {
      learnedPatterns.value.set(key, {
        input: key,
        command,
        successCount: 1,
        failCount: 0,
        lastUsed: Date.now()
      });
    }

    saveLearnedPatterns();
  }

  /**
   * Record failed command execution
   */
  function recordFailure(input: string, command: string) {
    const key = input.trim().toLowerCase();
    const existing = learnedPatterns.value.get(key);

    if (existing) {
      existing.failCount++;
    } else {
      learnedPatterns.value.set(key, {
        input: key,
        command,
        successCount: 0,
        failCount: 1,
        lastUsed: Date.now()
      });
    }

    saveLearnedPatterns();
  }

  /**
   * Should this command auto-execute without confirmation?
   */
  function shouldAutoExecute(match: CommandMatch): boolean {
    // High confidence + safe = auto-execute
    if (match.confidence >= 0.95 && match.safe) {
      return true;
    }

    // Rule-based with high confidence = auto-execute for read-only
    if (match.source === 'rule' && match.confidence >= 0.9 && match.safe) {
      return true;
    }

    return false;
  }

  /**
   * Get stats about learned patterns
   */
  function getStats() {
    const patterns = Array.from(learnedPatterns.value.values());
    return {
      totalLearned: patterns.length,
      successfulPatterns: patterns.filter(p => p.successCount > p.failCount).length,
      totalExecutions: patterns.reduce((sum, p) => sum + p.successCount + p.failCount, 0),
      ruleCount: COMMAND_RULES.length
    };
  }

  return {
    findCommand,
    recordSuccess,
    recordFailure,
    shouldAutoExecute,
    getStats,
    learnedPatterns
  };
}

export default useSmartCommands;

#!/usr/bin/env node
/**
 * Autonomous Development Loop
 *
 * This script creates an infinite development loop:
 * 1. Ask ChatGPT for the next task
 * 2. Spawn Claude Code to implement it
 * 3. Report results back to ChatGPT
 * 4. Repeat forever
 *
 * Usage: node autonomous_dev.cjs [thread_id]
 *
 * Requirements:
 * - chatgpt_thread_manager.cjs in same directory
 * - Claude Code CLI installed and configured
 */

const { spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Configuration
const CONFIG = {
  threadId: process.argv[2] || '693f18ee-0290-8329-956d-2f873f9308b4',
  projectDir: __dirname,
  taskFile: path.join(__dirname, '.autonomous_tasks.json'),
  logFile: path.join(__dirname, '.autonomous_dev.log'),
  pollInterval: 30000, // 30 seconds between ChatGPT polls
  claudeTimeout: 600000, // 10 minutes max per Claude session
  maxRetries: 3,
};

// Logging
function log(level, message) {
  const timestamp = new Date().toISOString();
  const line = `[${timestamp}] [${level}] ${message}`;
  console.log(line);
  fs.appendFileSync(CONFIG.logFile, line + '\n');
}

// Send message to ChatGPT and get response
async function askChatGPT(message) {
  return new Promise((resolve, reject) => {
    try {
      const result = execSync(
        `node chatgpt_thread_manager.cjs send "${CONFIG.threadId}" "${message.replace(/"/g, '\\"')}"`,
        {
          cwd: CONFIG.projectDir,
          encoding: 'utf8',
          timeout: 120000,
          maxBuffer: 10 * 1024 * 1024
        }
      );

      // Parse response
      const jsonMatch = result.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        resolve(parsed.response || parsed);
      } else {
        resolve(result);
      }
    } catch (error) {
      reject(error);
    }
  });
}

// Run Claude Code with a prompt
async function runClaude(prompt) {
  return new Promise((resolve, reject) => {
    log('INFO', 'Starting Claude Code session...');

    const claude = spawn('claude', [
      '--dangerously-skip-permissions',
      '-p', prompt
    ], {
      cwd: CONFIG.projectDir,
      timeout: CONFIG.claudeTimeout,
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    let errorOutput = '';

    claude.stdout.on('data', (data) => {
      const text = data.toString();
      output += text;
      process.stdout.write(text); // Stream to console
    });

    claude.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    claude.on('close', (code) => {
      if (code === 0) {
        resolve(output);
      } else {
        reject(new Error(`Claude exited with code ${code}: ${errorOutput}`));
      }
    });

    claude.on('error', (err) => {
      reject(err);
    });

    // Timeout handling
    setTimeout(() => {
      claude.kill('SIGTERM');
      reject(new Error('Claude session timed out'));
    }, CONFIG.claudeTimeout);
  });
}

// Load task state
function loadTaskState() {
  try {
    if (fs.existsSync(CONFIG.taskFile)) {
      return JSON.parse(fs.readFileSync(CONFIG.taskFile, 'utf8'));
    }
  } catch (e) {
    log('WARN', `Failed to load task state: ${e.message}`);
  }
  return {
    lastTask: null,
    completedTasks: [],
    failedTasks: [],
    sessionCount: 0
  };
}

// Save task state
function saveTaskState(state) {
  fs.writeFileSync(CONFIG.taskFile, JSON.stringify(state, null, 2));
}

// Extract actionable task from ChatGPT response
function extractTask(response) {
  // Look for code blocks or numbered lists
  const codeBlockMatch = response.match(/```[\s\S]*?```/);
  const numberedMatch = response.match(/(?:1\.|Step 1|First)[^\n]+/i);

  // If response contains specific instructions, use them
  if (response.toLowerCase().includes('implement') ||
      response.toLowerCase().includes('create') ||
      response.toLowerCase().includes('add') ||
      response.toLowerCase().includes('fix')) {
    return response;
  }

  return null;
}

// Main autonomous loop
async function autonomousLoop() {
  log('INFO', '=== Starting Autonomous Development Loop ===');
  log('INFO', `Thread ID: ${CONFIG.threadId}`);
  log('INFO', `Project: ${CONFIG.projectDir}`);

  const state = loadTaskState();
  state.sessionCount++;
  saveTaskState(state);

  while (true) {
    try {
      // Step 1: Ask ChatGPT for the next task
      log('INFO', 'Asking ChatGPT for next task...');

      const prompt = state.lastTask
        ? `The last task "${state.lastTask}" has been completed. What should I work on next for Warp_Open? Give me a specific, actionable task.`
        : `I'm ready to continue developing Warp_Open autonomously. What's the highest priority task I should work on next? Be specific and actionable.`;

      const chatGPTResponse = await askChatGPT(prompt);
      log('INFO', `ChatGPT Response: ${chatGPTResponse.substring(0, 200)}...`);

      const task = extractTask(chatGPTResponse);

      if (!task) {
        log('INFO', 'No actionable task found, waiting before retry...');
        await new Promise(r => setTimeout(r, CONFIG.pollInterval));
        continue;
      }

      // Step 2: Run Claude Code to implement the task
      log('INFO', `Implementing task: ${task.substring(0, 100)}...`);

      const claudePrompt = `You are working on Warp_Open, a terminal application built with Tauri + Vue 3.

Current task from ChatGPT orchestrator:
${task}

Instructions:
1. Implement this task completely
2. Run builds to verify (npm run build, cargo build)
3. When done, provide a brief summary of what you implemented

Do NOT ask questions - make reasonable decisions and proceed.`;

      const claudeResult = await runClaude(claudePrompt);

      // Step 3: Report results back to ChatGPT
      log('INFO', 'Reporting results to ChatGPT...');

      const summary = claudeResult.length > 2000
        ? claudeResult.substring(claudeResult.length - 2000)
        : claudeResult;

      await askChatGPT(`Task completed. Here's the summary:\n\n${summary}\n\nWhat's next?`);

      // Update state
      state.lastTask = task.substring(0, 100);
      state.completedTasks.push({
        task: state.lastTask,
        timestamp: new Date().toISOString()
      });
      saveTaskState(state);

      log('INFO', 'Task completed successfully!');

    } catch (error) {
      log('ERROR', `Loop error: ${error.message}`);

      // Record failure
      const state = loadTaskState();
      state.failedTasks.push({
        error: error.message,
        timestamp: new Date().toISOString()
      });
      saveTaskState(state);

      // Wait before retrying
      await new Promise(r => setTimeout(r, CONFIG.pollInterval * 2));
    }

    // Small delay between iterations
    await new Promise(r => setTimeout(r, 5000));
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  log('INFO', 'Received SIGINT, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  log('INFO', 'Received SIGTERM, shutting down gracefully...');
  process.exit(0);
});

// Start the loop
autonomousLoop().catch(err => {
  log('FATAL', `Autonomous loop crashed: ${err.message}`);
  process.exit(1);
});

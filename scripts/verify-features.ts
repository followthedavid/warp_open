/**
 * Feature Verification Script
 * Tests v1.1 and v1.2 features end-to-end
 */

import { TASK_ANALYSIS_PROMPT, COMMAND_GEN_PROMPT, applyTemplate, extractJSON, detectIntent, validateCommandOutput } from '../src/composables/usePromptTemplates';

async function testPromptTemplates() {
  console.log('\n=== Testing Prompt Templates ===\n');

  // Test intent detection (fast path)
  const intents = [
    { input: 'list files', expected: 'FILE' },
    { input: 'git status', expected: 'GIT' },
    { input: 'npm install', expected: 'NPM' },
    { input: 'what is typescript?', expected: 'QUESTION' },
    { input: 'hello', expected: 'CHAT' },
  ];

  let passed = 0;
  for (const { input, expected } of intents) {
    const result = detectIntent(input);
    const ok = result === expected;
    console.log(`  ${ok ? '✓' : '✗'} detectIntent("${input}") = ${result} (expected: ${expected})`);
    if (ok) passed++;
  }
  console.log(`\n  Intent detection: ${passed}/${intents.length} passed`);

  // Test JSON extraction
  console.log('\n  Testing JSON extraction...');
  const jsonTests = [
    '{"key": "value"}',
    '```json\n{"key": "value"}\n```',
    'Some text [{"type":"command","content":"ls"}] more text',
    "{'key': 'value'}",  // Single quotes
  ];

  for (const input of jsonTests) {
    const result = extractJSON(input);
    console.log(`  ${result ? '✓' : '✗'} extractJSON works for: ${input.substring(0, 30)}...`);
  }

  // Test validateCommandOutput
  console.log('\n  Testing command validation...');
  const validations = [
    { input: [{ type: 'command', content: 'ls -la' }], shouldPass: true },
    { input: { type: 'command', content: 'pwd' }, shouldPass: true },  // Not array
    { input: null, shouldPass: false },
    { input: [], shouldPass: false },
  ];

  for (const { input, shouldPass } of validations) {
    const result = validateCommandOutput(input);
    const ok = result.valid === shouldPass;
    console.log(`  ${ok ? '✓' : '✗'} validateCommandOutput: valid=${result.valid} (expected: ${shouldPass})`);
  }
}

async function testOllamaIntegration() {
  console.log('\n=== Testing Ollama Integration ===\n');

  const prompt = applyTemplate(COMMAND_GEN_PROMPT, 'list files');
  console.log('  Prompt:', prompt.substring(0, 100) + '...');

  try {
    const response = await fetch('http://localhost:11434/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'qwen2.5-coder:1.5b',
        prompt,
        stream: false,
      }),
    });

    if (!response.ok) {
      console.log('  ✗ Ollama request failed:', response.status);
      return;
    }

    const data = await response.json();
    console.log('  ✓ Ollama responded');
    console.log('  Raw response:', data.response.substring(0, 200));

    const parsed = extractJSON(data.response);
    console.log('  Parsed JSON:', JSON.stringify(parsed));

    const validation = validateCommandOutput(parsed);
    console.log('  ✓ Validation:', validation.valid ? 'PASSED' : 'FAILED');

    if (validation.valid) {
      console.log('  Generated command:', validation.steps[0]?.content);
    }
  } catch (error) {
    console.log('  ✗ Error:', error);
  }
}

async function testSmartCommands() {
  console.log('\n=== Testing Smart Commands ===\n');

  // Import dynamically to avoid module issues
  const commands = [
    'list files',
    'show date',
    'git status',
    'npm test',
    'docker ps',
    'what is my ip',
    'disk space',
  ];

  console.log('  Testing rule-based command matching (simulated):');
  for (const cmd of commands) {
    const intent = detectIntent(cmd);
    console.log(`  • "${cmd}" → intent: ${intent}`);
  }
}

async function main() {
  console.log('╔════════════════════════════════════════════╗');
  console.log('║  Warp Open v1.1/v1.2 Feature Verification  ║');
  console.log('╚════════════════════════════════════════════╝');

  await testPromptTemplates();
  await testSmartCommands();
  await testOllamaIntegration();

  console.log('\n=== Verification Complete ===\n');
}

main().catch(console.error);

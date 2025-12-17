#!/usr/bin/env node
// Send a message to Warp_Open via WebSocket test bridge

import WebSocket from 'ws';

const message = process.argv[2] || 'read my zshrc file';
const WS_PORT = process.env.WARP_OPEN_WS_PORT || 9223;

console.log(`Connecting to test bridge on port ${WS_PORT}...`);

const ws = new WebSocket(`ws://localhost:${WS_PORT}`);

ws.on('open', () => {
  console.log('✓ Connected to test bridge');
  console.log(`Sending message: "${message}"`);
  
  ws.send(JSON.stringify({
    type: 'send_message',
    content: message
  }));
  
  // Wait a bit for confirmation then close
  setTimeout(() => {
    console.log('✓ Message sent');
    ws.close();
    process.exit(0);
  }, 500);
});

ws.on('message', (data) => {
  const msg = JSON.parse(data.toString());
  console.log('Received:', msg.type);
  
  if (msg.type === 'ready') {
    console.log('✓ Test bridge ready');
  }
});

ws.on('error', (error) => {
  console.error('✗ WebSocket error:', error.message);
  console.error('\nMake sure:');
  console.error('1. Warp_Open is running with WARP_OPEN_TEST_MODE=1');
  console.error('2. Test bridge is enabled on port', WS_PORT);
  process.exit(1);
});

ws.on('close', () => {
  console.log('Connection closed');
});

// Timeout after 5 seconds
setTimeout(() => {
  console.error('✗ Connection timeout');
  process.exit(1);
}, 5000);

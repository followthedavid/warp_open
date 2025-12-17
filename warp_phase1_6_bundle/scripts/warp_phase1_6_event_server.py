#!/usr/bin/env python3
"""
Warp Phase 1-6 Parallel Event Server
Streams events from scheduler, alerts, and ML safety checks
to the live dashboard via WebSocket.

Usage:
    python3 warp_phase1_6_event_server.py [--port 9000]
"""

import asyncio
import json
import websockets
import argparse
import sys
from datetime import datetime
from pathlib import Path

PORT = 9000
clients = set()
event_log = []
MAX_LOG_SIZE = 1000

async def broadcast(msg):
    """Broadcast message to all connected clients"""
    if clients:
        disconnected = set()
        for client in clients:
            try:
                await client.send(msg)
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(client)
        
        # Remove disconnected clients
        clients.difference_update(disconnected)

async def handler(websocket):
    """Handle new WebSocket connections"""
    clients.add(websocket)
    client_addr = websocket.remote_address
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] New client connected: {client_addr}")
    
    # Send connection confirmation
    welcome_msg = {
        "phase": "system",
        "event": f"Connected to Warp Phase 1-6 event server ({len(clients)} clients)",
        "type": "success",
        "timestamp": datetime.now().isoformat()
    }
    await websocket.send(json.dumps(welcome_msg))
    
    # Send recent event history
    for event in event_log[-50:]:  # Send last 50 events
        try:
            await websocket.send(event)
        except:
            pass
    
    try:
        # Listen for incoming messages from client
        async for message in websocket:
            try:
                data = json.loads(message)
                
                # Add timestamp if not present
                if 'timestamp' not in data:
                    data['timestamp'] = datetime.now().isoformat()
                
                # Log the event
                event_json = json.dumps(data)
                event_log.append(event_json)
                if len(event_log) > MAX_LOG_SIZE:
                    event_log.pop(0)
                
                # Broadcast to all other clients
                await broadcast(event_json)
                
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Phase {data.get('phase', '?')}: {data.get('event', 'Unknown event')}")
                
            except json.JSONDecodeError:
                print(f"Invalid JSON received: {message}")
            except Exception as e:
                print(f"Error processing message: {e}")
                
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        clients.remove(websocket)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Client disconnected: {client_addr} ({len(clients)} remaining)")

async def periodic_heartbeat():
    """Send periodic heartbeat to keep connections alive"""
    while True:
        await asyncio.sleep(30)
        if clients:
            heartbeat = {
                "phase": "system",
                "event": f"Server heartbeat ({len(clients)} clients connected)",
                "type": "info",
                "timestamp": datetime.now().isoformat()
            }
            await broadcast(json.dumps(heartbeat))

async def main(port):
    """Start WebSocket server"""
    print("="*70)
    print(f"Warp Phase 1-6 WebSocket Event Server")
    print(f"Listening on ws://localhost:{port}")
    print(f"Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    print()
    print("Waiting for clients to connect...")
    print("Press Ctrl+C to stop")
    print()
    
    # Start WebSocket server
    async with websockets.serve(handler, "0.0.0.0", port):
        # Start heartbeat task
        heartbeat_task = asyncio.create_task(periodic_heartbeat())
        
        try:
            await asyncio.Future()  # Run forever
        except KeyboardInterrupt:
            print("\n\nShutting down server...")
            heartbeat_task.cancel()
            
            # Notify all clients
            shutdown_msg = {
                "phase": "system",
                "event": "Server shutting down",
                "type": "warn",
                "timestamp": datetime.now().isoformat()
            }
            await broadcast(json.dumps(shutdown_msg))
            
            print(f"Disconnected {len(clients)} clients")
            print("Server stopped")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Warp Phase 1-6 WebSocket Event Server')
    parser.add_argument('--port', type=int, default=PORT, help=f'WebSocket port (default: {PORT})')
    args = parser.parse_args()
    
    try:
        asyncio.run(main(args.port))
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(0)

/**
 * E2E tests for Warp_Open AI tool calling
 * 
 * Tests that AI tool calls execute correctly without duplication or infinite thinking
 */

import { spawn, ChildProcess } from 'child_process'
import { WebSocket } from 'ws'
import * as path from 'path'
import * as fs from 'fs'

interface Message {
  id: number
  role: 'user' | 'ai' | 'system'
  content: string
  timestamp: number
}

interface TestResult {
  passed: boolean
  error?: string
  messages?: Message[]
  duration?: number
}

class WarpOpenTester {
  private appProcess: ChildProcess | null = null
  private ws: WebSocket | null = null
  private messageLog: Message[] = []
  
  async launch(): Promise<void> {
    const appPath = path.join(__dirname, '../src-tauri/target/release/bundle/dmg/Warp_Open.app/Contents/MacOS/Warp_Open')
    
    return new Promise((resolve, reject) => {
      this.appProcess = spawn(appPath, [], {
        env: {
          ...process.env,
          WARP_OPEN_TEST_MODE: '1',
          WARP_OPEN_WS_PORT: '9223'
        }
      })
      
      this.appProcess.on('error', reject)
      
      // Wait for app to start, then connect via WebSocket
      setTimeout(() => {
        this.connectWebSocket()
          .then(resolve)
          .catch(reject)
      }, 2000)
    })
  }
  
  private async connectWebSocket(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket('ws://localhost:9223')
      
      this.ws.on('open', () => {
        console.log('[Tester] Connected to Warp_Open')
        resolve()
      })
      
      this.ws.on('message', (data) => {
        const msg = JSON.parse(data.toString())
        if (msg.type === 'message') {
          this.messageLog.push(msg.data)
        }
      })
      
      this.ws.on('error', reject)
    })
  }
  
  async sendMessage(content: string): Promise<void> {
    if (!this.ws) throw new Error('WebSocket not connected')
    
    this.ws.send(JSON.stringify({
      type: 'send_message',
      content
    }))
  }
  
  async waitForResponse(timeoutMs: number = 10000): Promise<void> {
    const startTime = Date.now()
    const initialCount = this.messageLog.length
    
    return new Promise((resolve, reject) => {
      const checkInterval = setInterval(() => {
        // Check if we got new messages and AI is done thinking
        if (this.messageLog.length > initialCount + 1) {
          const lastMsg = this.messageLog[this.messageLog.length - 1]
          if (lastMsg.role === 'ai') {
            clearInterval(checkInterval)
            resolve()
            return
          }
        }
        
        if (Date.now() - startTime > timeoutMs) {
          clearInterval(checkInterval)
          reject(new Error('Response timeout'))
        }
      }, 100)
    })
  }
  
  getMessagesSince(startIndex: number): Message[] {
    return this.messageLog.slice(startIndex)
  }
  
  async cleanup(): Promise<void> {
    if (this.ws) {
      this.ws.close()
    }
    if (this.appProcess) {
      this.appProcess.kill()
    }
  }
}

async function testReadFile(): Promise<TestResult> {
  const tester = new WarpOpenTester()
  const startTime = Date.now()
  
  try {
    await tester.launch()
    
    const startMsgCount = tester.getMessagesSince(0).length
    await tester.sendMessage('read my zshrc file')
    await tester.waitForResponse(15000)
    
    const messages = tester.getMessagesSince(startMsgCount)
    
    // Validate expectations:
    // 1. Should have user message, tool call, tool result, AI response
    // 2. Tool call should appear exactly once
    // 3. Tool result should appear exactly once
    // 4. Should have a final AI text response
    // 5. No duplicate tool calls
    
    const toolCalls = messages.filter(m => 
      m.role === 'ai' && m.content.includes('"tool"') && m.content.includes('read_file')
    )
    const toolResults = messages.filter(m => 
      m.role === 'system' && m.content.includes('[Tool executed: read_file]')
    )
    const aiResponses = messages.filter(m => 
      m.role === 'ai' && !m.content.includes('"tool"')
    )
    
    const checks = [
      { name: 'Exactly one tool call', pass: toolCalls.length === 1 },
      { name: 'Exactly one tool result', pass: toolResults.length === 1 },
      { name: 'Has AI text response', pass: aiResponses.length >= 1 },
      { name: 'AI response is not empty', pass: aiResponses.length > 0 && aiResponses[0].content.trim().length > 0 },
      { name: 'No duplicate messages', pass: new Set(messages.map(m => `${m.role}:${m.content}`)).size === messages.length }
    ]
    
    const failed = checks.filter(c => !c.pass)
    
    if (failed.length > 0) {
      return {
        passed: false,
        error: `Failed checks: ${failed.map(c => c.name).join(', ')}`,
        messages,
        duration: Date.now() - startTime
      }
    }
    
    return {
      passed: true,
      messages,
      duration: Date.now() - startTime
    }
    
  } catch (error) {
    return {
      passed: false,
      error: error instanceof Error ? error.message : String(error),
      duration: Date.now() - startTime
    }
  } finally {
    await tester.cleanup()
  }
}

async function testWriteFile(): Promise<TestResult> {
  const tester = new WarpOpenTester()
  const startTime = Date.now()
  const testFile = '/tmp/warp_test_' + Date.now() + '.txt'
  
  try {
    await tester.launch()
    
    const startMsgCount = tester.getMessagesSince(0).length
    await tester.sendMessage(`write "hello world" to ${testFile}`)
    await tester.waitForResponse(15000)
    
    const messages = tester.getMessagesSince(startMsgCount)
    
    const toolCalls = messages.filter(m => 
      m.role === 'ai' && m.content.includes('"tool"') && m.content.includes('write_file')
    )
    
    // Verify file was actually written
    const fileExists = fs.existsSync(testFile)
    const fileContent = fileExists ? fs.readFileSync(testFile, 'utf-8') : ''
    
    const checks = [
      { name: 'Exactly one tool call', pass: toolCalls.length === 1 },
      { name: 'File was created', pass: fileExists },
      { name: 'File has correct content', pass: fileContent.includes('hello world') }
    ]
    
    const failed = checks.filter(c => !c.pass)
    
    // Cleanup test file
    if (fileExists) fs.unlinkSync(testFile)
    
    if (failed.length > 0) {
      return {
        passed: false,
        error: `Failed checks: ${failed.map(c => c.name).join(', ')}`,
        messages,
        duration: Date.now() - startTime
      }
    }
    
    return {
      passed: true,
      messages,
      duration: Date.now() - startTime
    }
    
  } catch (error) {
    return {
      passed: false,
      error: error instanceof Error ? error.message : String(error),
      duration: Date.now() - startTime
    }
  } finally {
    await tester.cleanup()
  }
}

async function runTests() {
  console.log('🧪 Starting Warp_Open E2E Tests\n')
  
  const tests = [
    { name: 'Read file tool call', fn: testReadFile },
    { name: 'Write file tool call', fn: testWriteFile }
  ]
  
  const results = []
  
  for (const test of tests) {
    console.log(`Running: ${test.name}...`)
    const result = await test.fn()
    results.push({ name: test.name, ...result })
    
    if (result.passed) {
      console.log(`✅ PASS (${result.duration}ms)`)
    } else {
      console.log(`❌ FAIL (${result.duration}ms)`)
      console.log(`   Error: ${result.error}`)
      if (result.messages) {
        console.log(`   Messages received: ${result.messages.length}`)
        result.messages.forEach(m => {
          console.log(`     [${m.role}] ${m.content.substring(0, 60)}...`)
        })
      }
    }
    console.log('')
  }
  
  const passed = results.filter(r => r.passed).length
  const failed = results.filter(r => !r.passed).length
  
  console.log(`\n📊 Results: ${passed} passed, ${failed} failed`)
  
  process.exit(failed > 0 ? 1 : 0)
}

runTests().catch(console.error)

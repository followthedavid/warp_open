import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { useToast } from './useToast'

describe('useToast', () => {
  beforeEach(() => {
    // Clear toasts before each test
    vi.useFakeTimers()
    const { clearAll } = useToast()
    clearAll()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('should add a toast notification', () => {
    const { toasts, addToast } = useToast()

    const id = addToast('success', 'Test message')

    expect(id).toBeDefined()
    expect(toasts.value).toHaveLength(1)
    expect(toasts.value[0].message).toBe('Test message')
    expect(toasts.value[0].type).toBe('success')
  })

  it('should add toast with title', () => {
    const { toasts, addToast } = useToast()

    addToast('error', 'Error message', { title: 'Error Title' })

    expect(toasts.value[0].title).toBe('Error Title')
  })

  it('should auto-dismiss toast after duration', () => {
    const { toasts, addToast } = useToast()

    addToast('info', 'Will dismiss', { duration: 1000 })

    expect(toasts.value).toHaveLength(1)

    vi.advanceTimersByTime(1000)

    expect(toasts.value).toHaveLength(0)
  })

  it('should not auto-dismiss when duration is 0', () => {
    const { toasts, addToast } = useToast()

    addToast('warning', 'Persistent', { duration: 0 })

    expect(toasts.value).toHaveLength(1)

    vi.advanceTimersByTime(10000)

    expect(toasts.value).toHaveLength(1)
  })

  it('should dismiss toast by ID', () => {
    const { toasts, addToast, dismissToast } = useToast()

    const id = addToast('success', 'Test', { duration: 0 })
    expect(toasts.value).toHaveLength(1)

    dismissToast(id)
    expect(toasts.value).toHaveLength(0)
  })

  it('should limit number of toasts', () => {
    const { toasts, addToast } = useToast()

    // Add more than MAX_TOASTS (5)
    for (let i = 0; i < 7; i++) {
      addToast('info', `Message ${i}`, { duration: 0 })
    }

    expect(toasts.value.length).toBeLessThanOrEqual(5)
  })

  it('should have convenience methods', () => {
    const { toasts, success, error, warning, info, clearAll } = useToast()

    success('Success message')
    expect(toasts.value[0].type).toBe('success')

    clearAll()
    error('Error message')
    expect(toasts.value[0].type).toBe('error')

    clearAll()
    warning('Warning message')
    expect(toasts.value[0].type).toBe('warning')

    clearAll()
    info('Info message')
    expect(toasts.value[0].type).toBe('info')
  })

  it('should clear all toasts', () => {
    const { toasts, addToast, clearAll } = useToast()

    addToast('success', 'One', { duration: 0 })
    addToast('info', 'Two', { duration: 0 })
    addToast('warning', 'Three', { duration: 0 })

    expect(toasts.value).toHaveLength(3)

    clearAll()
    expect(toasts.value).toHaveLength(0)
  })

  it('should add newest toast first', () => {
    const { toasts, addToast } = useToast()

    addToast('info', 'First', { duration: 0 })
    addToast('info', 'Second', { duration: 0 })
    addToast('info', 'Third', { duration: 0 })

    expect(toasts.value[0].message).toBe('Third')
    expect(toasts.value[2].message).toBe('First')
  })
})

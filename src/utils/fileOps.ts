/**
 * File operation utilities for autonomous execution
 * Uses Tauri file system APIs for secure file access
 */

// Check if Tauri is available
const isTauri = typeof window !== 'undefined' && '__TAURI__' in window;

/**
 * Sandboxed directory whitelist
 * Only these directories are allowed for file operations
 */
const ALLOWED_DIRECTORIES = [
  '/Users/davidquinton/ReverseLab/Warp_Open/warp_tauri/src',
  '/Users/davidquinton/ReverseLab/Warp_Open/warp_tauri/tests',
  '/Users/davidquinton/ReverseLab/Warp_Open/warp_tauri/docs',
];

/**
 * Check if a path is within allowed directories
 */
function isPathAllowed(path: string): boolean {
  const normalizedPath = path.replace(/\\/g, '/');
  return ALLOWED_DIRECTORIES.some(dir => normalizedPath.startsWith(dir));
}

/**
 * Read file contents safely
 */
export async function readFile(path: string): Promise<string> {
  if (!isPathAllowed(path)) {
    throw new Error(`Access denied: ${path} is outside allowed directories`);
  }

  if (isTauri) {
    // Use Tauri file system API
    const { readTextFile } = await import('@tauri-apps/api/fs');
    return await readTextFile(path);
  } else {
    // Fallback for browser mode (development only)
    const response = await fetch(`/api/files/read?path=${encodeURIComponent(path)}`);
    if (!response.ok) {
      throw new Error(`Failed to read file: ${response.statusText}`);
    }
    return await response.text();
  }
}

/**
 * Write file contents safely
 */
export async function writeFile(path: string, content: string): Promise<void> {
  if (!isPathAllowed(path)) {
    throw new Error(`Access denied: ${path} is outside allowed directories`);
  }

  if (isTauri) {
    // Use Tauri file system API
    const { writeTextFile } = await import('@tauri-apps/api/fs');
    await writeTextFile(path, content);
  } else {
    // Fallback for browser mode (development only)
    const response = await fetch('/api/files/write', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, content }),
    });
    if (!response.ok) {
      throw new Error(`Failed to write file: ${response.statusText}`);
    }
  }
}

/**
 * List directory contents
 */
export async function listDirectory(path: string): Promise<string[]> {
  if (!isPathAllowed(path)) {
    throw new Error(`Access denied: ${path} is outside allowed directories`);
  }

  if (isTauri) {
    const { readDir } = await import('@tauri-apps/api/fs');
    const entries = await readDir(path);
    return entries.map(entry => entry.name || '');
  } else {
    const response = await fetch(`/api/files/list?path=${encodeURIComponent(path)}`);
    if (!response.ok) {
      throw new Error(`Failed to list directory: ${response.statusText}`);
    }
    return await response.json();
  }
}

/**
 * Check if file exists
 */
export async function fileExists(path: string): Promise<boolean> {
  if (!isPathAllowed(path)) {
    return false;
  }

  try {
    if (isTauri) {
      const { exists } = await import('@tauri-apps/api/fs');
      return await exists(path);
    } else {
      const response = await fetch(`/api/files/exists?path=${encodeURIComponent(path)}`);
      return response.ok;
    }
  } catch {
    return false;
  }
}

/**
 * Create a backup snapshot of a file before modification
 */
export async function createSnapshot(path: string): Promise<string | null> {
  try {
    const content = await readFile(path);
    return content;
  } catch {
    return null;
  }
}

/**
 * Restore a file from snapshot
 */
export async function restoreSnapshot(path: string, snapshot: string): Promise<void> {
  await writeFile(path, snapshot);
}

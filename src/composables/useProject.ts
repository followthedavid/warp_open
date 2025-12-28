import { computed, ref } from 'vue'
import { invoke } from '@tauri-apps/api/tauri'
import { open } from '@tauri-apps/api/dialog'

export type FileNode = {
  path: string
  name: string
  kind: 'file' | 'dir'
  children?: FileNode[]
}

const projectRoot = ref<string | null>(null)
const projectTree = ref<FileNode[]>([])
const isLoadingTree = ref(false)

async function ensureInitialRoot() {
  if (projectRoot.value) return
  try {
    const cwd = await invoke<string>('current_working_dir')
    projectRoot.value = cwd
  } catch (error) {
    console.warn('[useProject] Failed to resolve cwd:', error)
  }
}

async function refreshProjectTree() {
  await ensureInitialRoot()
  if (!projectRoot.value) {
    projectTree.value = []
    return []
  }

  try {
    isLoadingTree.value = true
    const tree = await invoke<FileNode[]>('list_directory_tree', { path: projectRoot.value })
    projectTree.value = tree
    return tree
  } catch (error) {
    console.error('[useProject] Failed to load directory tree:', error)
    projectTree.value = []
    return []
  } finally {
    isLoadingTree.value = false
  }
}

async function pickProjectFolder() {
  const selection = await open({
    directory: true,
    multiple: false,
    title: 'Select project folder'
  })

  if (typeof selection === 'string') {
    projectRoot.value = selection
    await refreshProjectTree()
  }
}

async function readFile(path: string) {
  try {
    return await invoke<string>('read_file', { path })
  } catch (error) {
    console.error('[useProject] readFile error:', error)
    return ''
  }
}

async function writeFile(path: string, content: string) {
  try {
    await invoke('write_file', { path, content })
    return true
  } catch (error) {
    console.error('[useProject] writeFile error:', error)
    return false
  }
}

const projectName = computed(() => {
  if (!projectRoot.value) return 'No project'
  const segments = projectRoot.value.split('/').filter(Boolean)
  return segments[segments.length - 1] || projectRoot.value
})

export function useProject() {
  return {
    projectRoot,
    projectTree,
    projectName,
    isLoadingTree,
    pickProjectFolder,
    refreshProjectTree,
    readFile,
    writeFile,
  }
}



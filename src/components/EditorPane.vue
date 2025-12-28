<template>
  <div class="editor-pane">
    <header class="editor-toolbar">
      <div class="meta">
        <span class="filename">{{ tab.name }}</span>
        <span v-if="tab.isDirty" class="dirty-dot">●</span>
        <span v-if="tab.filePath" class="filepath">{{ tab.filePath }}</span>
      </div>
      <div class="actions">
        <button @click="saveFile" data-testid="editor-save">Save</button>
        <button @click="$emit('run')" data-testid="editor-run">Run</button>
      </div>
    </header>
    <div class="editor-container" ref="editorContainer"></div>
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, watch, ref } from 'vue'
import * as monaco from 'monaco-editor'
import type { Tab } from '../composables/useTabs'
import { useEditorModels } from '../composables/useEditor'
import { useTabs } from '../composables/useTabs'
import { useProject } from '../composables/useProject'

const props = defineProps<{
  tab: Tab
}>()

defineEmits(['run'])

const editorContainer = ref<HTMLElement | null>(null)
let editorInstance: monaco.editor.IStandaloneCodeEditor | null = null
const { getOrCreateModel, disposeModel } = useEditorModels()
const { updateEditorContent, markEditorSaved } = useTabs()
const { writeFile } = useProject()

function languageFromPath(path?: string) {
  if (!path) return 'plaintext'
  if (path.endsWith('.ts') || path.endsWith('.tsx')) return 'typescript'
  if (path.endsWith('.js') || path.endsWith('.mjs')) return 'javascript'
  if (path.endsWith('.json')) return 'json'
  if (path.endsWith('.rs')) return 'rust'
  if (path.endsWith('.py')) return 'python'
  if (path.endsWith('.vue')) return 'vue'
  if (path.endsWith('.md')) return 'markdown'
  return 'plaintext'
}

function initEditor() {
  if (!editorContainer.value) return
  const modelKey = props.tab.filePath ?? `untitled-${props.tab.id}`
  const model = getOrCreateModel(modelKey, props.tab.content ?? '', languageFromPath(props.tab.filePath))
  if (props.tab.content != null && model.getValue() !== props.tab.content) {
    model.setValue(props.tab.content)
  }

  editorInstance = monaco.editor.create(editorContainer.value, {
    model,
    automaticLayout: true,
    minimap: { enabled: false },
    fontSize: 13,
    theme: 'vs-dark',
  })

  editorInstance.onDidChangeModelContent(() => {
    const value = editorInstance?.getValue() ?? ''
    updateEditorContent(props.tab.id, value)
  })
}

async function saveFile() {
  if (!editorInstance || !props.tab.filePath) {
    console.warn('[EditorPane] Cannot save: missing file path')
    return
  }
  const value = editorInstance.getValue()
  const success = await writeFile(props.tab.filePath, value)
  if (success) {
    markEditorSaved(props.tab.id, value)
  }
}

onMounted(() => {
  initEditor()
})

onBeforeUnmount(() => {
  if (props.tab.filePath) {
    disposeModel(props.tab.filePath)
  } else {
    disposeModel(`untitled-${props.tab.id}`)
  }
  editorInstance?.dispose()
  editorInstance = null
})

watch(
  () => props.tab.id,
  () => {
    editorInstance?.dispose()
    editorInstance = null
    initEditor()
  }
)

watch(
  () => props.tab.content,
  (content) => {
    if (!editorInstance || content == null) return
    const current = editorInstance.getValue()
    if (current !== content) {
      const model = editorInstance.getModel()
      model?.setValue(content)
    }
  }
)
</script>

<style scoped>
.editor-pane {
  display: flex;
  flex-direction: column;
  width: 100%;
  height: 100%;
}

.editor-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 12px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  background: #0a1224;
}

.meta {
  display: flex;
  align-items: center;
  gap: 6px;
}

.filename {
  font-weight: 500;
}

.filepath {
  font-size: 12px;
  color: #8d98b3;
}

.dirty-dot {
  color: #facc15;
  font-size: 10px;
}

.actions button {
  background: #202b45;
  border: none;
  color: #e2e8f0;
  padding: 4px 10px;
  border-radius: 4px;
  margin-left: 6px;
  cursor: pointer;
}

.editor-container {
  flex: 1;
  min-height: 0;
}
</style>



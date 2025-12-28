import * as monaco from 'monaco-editor'

const models = new Map<string, monaco.editor.ITextModel>()

function modelUriForKey(key: string) {
  if (key.startsWith('file://')) return monaco.Uri.parse(key)
  return monaco.Uri.parse(`file://${key}`)
}

export function useEditorModels() {
  function getOrCreateModel(pathOrId: string, initialValue = '', language = 'plaintext') {
    const uri = modelUriForKey(pathOrId)
    const key = uri.toString()
    if (models.has(key)) {
      return models.get(key)!
    }
    const model = monaco.editor.createModel(initialValue, language, uri)
    models.set(key, model)
    return model
  }

  function disposeModel(pathOrId: string) {
    const uri = modelUriForKey(pathOrId)
    const key = uri.toString()
    const model = models.get(key)
    if (model) {
      model.dispose()
      models.delete(key)
    }
  }

  return {
    getOrCreateModel,
    disposeModel,
  }
}



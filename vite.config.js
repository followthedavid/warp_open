import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    vue(),
    // Monaco editor plugin temporarily disabled - can re-enable later if needed
    // monacoEditorPlugin({
    //   languageWorkers: ['editorWorkerService', 'typescript', 'javascript'],
    // }),
  ],

  // Vite options tailored for Tauri development
  clearScreen: false,

  // Tauri expects a fixed port, fail if that port is not available
  server: {
    port: 5173,
    strictPort: true,
    fs: {
      strict: false,
    },
  },

  // to access the Tauri environment variables set by the CLI with information about the current target
  envPrefix: ['VITE_', 'TAURI_'],

  build: {
    // Tauri uses Chromium on Windows and WebKit on macOS and Linux
    target: process.env.TAURI_PLATFORM == 'windows' ? 'chrome105' : 'safari13',
    // don't minify for debug builds
    minify: !process.env.TAURI_DEBUG ? 'esbuild' : false,
    // produce sourcemaps for debug builds
    sourcemap: !!process.env.TAURI_DEBUG,

    // Code-splitting configuration for better bundle size
    rollupOptions: {
      output: {
        manualChunks: {
          // Monaco editor is large - put it in its own chunk
          'monaco': ['monaco-editor'],
          // xterm.js terminal - separate chunk
          'xterm': ['xterm', 'xterm-addon-fit', 'xterm-addon-web-links', 'xterm-addon-webgl'],
          // Vue core - separate chunk
          'vue-vendor': ['vue', '@vue/runtime-core', '@vue/runtime-dom'],
        },
      },
    },
    // Suppress warning for large chunks (we know Monaco is big)
    chunkSizeWarningLimit: 1000,
  },

  // Strip console.log/warn/debug in production builds
  esbuild: {
    drop: process.env.TAURI_DEBUG ? [] : ['console', 'debugger'],
  },
})

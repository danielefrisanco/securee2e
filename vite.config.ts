import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

export default defineConfig({
  plugins: [vue()],
  test: {
    globals: true, // Use global APIs like 'it', 'expect'
    environment: 'jsdom', // CRITICAL: Enables browser environment for 'window'
  },
  build: {
    lib: {
      // Changed entry to .ts file
      entry: resolve(__dirname, 'src/index.ts'), 
      name: 'securee2e',
      fileName: 'securee2e'
    },
    rollupOptions: {
      external: ['vue'],
      output: {
        globals: {
          vue: 'Vue'
        }
      }
    }
  }
})
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

export default defineConfig({
  plugins: [vue()],
  test: {
    globals: true, // Use global APIs like 'it', 'expect'
    environment: 'jsdom', // CRITICAL: Enables browser environment for 'window'
    // CRITICAL: Tells Vitest where to find the setup file
    setupFiles: [
      './vitest.setup.js'
    ],
    // Glob patterns for finding test files
    include: ['__tests__/**/*.{ts,js}'],
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
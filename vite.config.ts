import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { resolve } from 'path';

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
      // Keeping the user's entry point, assuming src/index.ts correctly re-exports everything
      entry: resolve(__dirname, 'src/index.ts'), 
      name: 'securee2e',
      // CRITICAL: Removed the generic fileName property to allow RollupOptions to control naming
    },
    rollupOptions: {
      external: ['vue'],
      // CRITICAL FIX: Explicitly define the output formats and file names
      output: [
        {
          format: 'es', // ES Module (for 'module' field in package.json)
          entryFileNames: 'securee2e.mjs',
          globals: { vue: 'Vue' }
        },
        {
          format: 'cjs', // CommonJS (for 'main' field in package.json)
          entryFileNames: 'securee2e.js',
          globals: { vue: 'Vue' }
        }
      ]
    }
  }
});

import { defineConfig } from 'vitest/config';
import vue from '@vitejs/plugin-vue';
import { fileURLToPath, URL } from 'node:url';

const src = (p: string) => fileURLToPath(new URL(`./src/${p}`, import.meta.url));

export default defineConfig(({ command }) => ({
  plugins: [vue()],

  // `vite` / `vite preview` serve the playground; `vite build` builds the library; vitest uses the project root.
  root: command === 'serve' && !process.env.VITEST ? 'playground' : undefined,

  resolve: {
    alias: {
      'securee2e/vue': src('vue.ts'),
      securee2e: src('index.ts'),
    },
  },

  build: {
    copyPublicDir: false,
    sourcemap: true,
    lib: {
      entry: {
        index: src('index.ts'),
        vue: src('vue.ts'),
      },
      formats: ['es', 'cjs'],
      // "type": "module" in package.json makes .js mean ESM, so CJS must be .cjs.
      fileName: (format, entryName) => `${entryName}.${format === 'es' ? 'mjs' : 'cjs'}`,
    },
    rollupOptions: {
      external: ['vue'],
      output: { globals: { vue: 'Vue' } },
    },
  },

  test: {
    environment: 'jsdom',
    setupFiles: ['fake-indexeddb/auto'],
    include: ['__tests__/**/*.test.ts'],
    coverage: {
      include: ['src/**/*.ts'],
      reporter: ['text', 'html'],
    },
  },
}));

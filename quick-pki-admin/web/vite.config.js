import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8090',
      '/callback': 'http://localhost:8090',
      '/config': 'http://localhost:8090'
    }
  }
})

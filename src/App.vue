<script setup lang="ts">
import { ref } from 'vue';
// We will create E2EChat.vue (Low-Level) and E2ESimplifiedChat.vue (High-Level)
import E2EChat from './E2EChat.vue';
import E2ESimplifiedChat from './E2ESimplifiedChat.vue';

// State to track which chat component to display
const activeChat = ref<'low-level' | 'high-level'>('low-level');

const title = {
  'low-level': 'securee2e Demo: Low-Level Workflow (6 Steps)',
  'high-level': 'securee2e Demo: High-Level Workflow (v0.3.1 Simplified API)',
};
</script>

<template>
  <main>
    <div class="demo-container">
      <h1 class="app-title">{{ title[activeChat] }}</h1>

      <div class="button-group">
        <button
          :class="{ active: activeChat === 'low-level' }"
          @click="activeChat = 'low-level'"
        >
          Low-Level Version
        </button>
        <button
          :class="{ active: activeChat === 'high-level' }"
          @click="activeChat = 'high-level'"
        >
          High-Level Version (v0.3.1)
        </button>
      </div>
      
      <E2EChat v-if="activeChat === 'low-level'" />
      <E2ESimplifiedChat v-if="activeChat === 'high-level'" />
    </div>
  </main>
</template>

<style>
/* Basic global styles to center the app */
body {
  margin: 0;
  background-color: #f4f7f6;
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: flex-start; /* Align to the top of the screen */
  padding-top: 50px;
  font-family: Arial, sans-serif;
}

.demo-container {
  width: 90%;
  max-width: 800px;
  background-color: #fff;
  padding: 30px;
  border-radius: 10px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.app-title {
  text-align: center;
  color: #333;
  font-size: 1.5rem;
  margin-bottom: 25px;
  border-bottom: 1px solid #eee;
  padding-bottom: 15px;
}

.button-group {
  display: flex;
  justify-content: center;
  gap: 15px;
  margin-bottom: 30px;
}

.button-group button {
  padding: 10px 20px;
  font-size: 1rem;
  cursor: pointer;
  border: 2px solid #2c3e50;
  background-color: #f9f9f9;
  color: #2c3e50;
  border-radius: 5px;
  transition: all 0.2s;
}

.button-group button:hover {
  background-color: #e8e8e8;
}

.button-group button.active {
  background-color: #42b883;
  border-color: #42b883;
  color: white;
  box-shadow: 0 2px 4px rgba(66, 184, 131, 0.3);
}
</style>
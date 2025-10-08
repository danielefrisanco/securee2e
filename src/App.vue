<script setup>
// 1. Import the new E2E Chat component
import E2EChat from './E2EChat.vue';
</script>

<template>
  <main>
    <!-- 2. Display the imported component -->
    <E2EChat />
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
}
</style>

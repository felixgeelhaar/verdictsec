<script setup lang="ts">
import { ref } from 'vue';

const props = defineProps<{
  text: string;
}>();

const copied = ref(false);

const copyToClipboard = async () => {
  try {
    await navigator.clipboard.writeText(props.text);
    copied.value = true;
    setTimeout(() => {
      copied.value = false;
    }, 2000);
  } catch (err) {
    console.error('Failed to copy:', err);
  }
};
</script>

<template>
  <button class="copy-btn" @click="copyToClipboard">
    {{ copied ? 'Copied!' : 'Copy' }}
  </button>
</template>

<style scoped>
.copy-btn {
  position: absolute;
  top: 0.75rem;
  right: 0.75rem;
  background: var(--bg-tertiary);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.375rem 0.625rem;
  font-size: 0.75rem;
  color: var(--text-secondary);
  cursor: pointer;
  transition: all 0.2s;
  font-family: var(--font-sans);
}

.copy-btn:hover {
  background: var(--bg-card);
  color: var(--text-primary);
}
</style>

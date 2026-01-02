<script setup lang="ts">
defineProps<{
  icon: string;
  name: string;
  type: string;
  description: string;
}>();
</script>

<template>
  <div class="engine-card">
    <div class="engine-header">
      <div class="engine-icon">{{ icon }}</div>
      <div class="engine-meta">
        <div class="engine-name">{{ name }}</div>
        <div class="engine-type">{{ type }}</div>
      </div>
      <div class="engine-status">
        <span class="engine-status-dot"></span>
        Active
      </div>
    </div>
    <p class="engine-description">{{ description }}</p>
  </div>
</template>

<style scoped>
.engine-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.75rem;
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;
}

.engine-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
  opacity: 0;
  transition: opacity 0.3s;
}

.engine-card:hover {
  border-color: var(--border-hover);
  transform: translateY(-2px);
  box-shadow: 0 10px 40px -20px rgba(0,0,0,0.3);
}

.engine-card:hover::before {
  opacity: 1;
}

.engine-header {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 1rem;
}

.engine-icon {
  width: 48px;
  height: 48px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border);
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: var(--font-mono);
  font-size: 1.25rem;
  font-weight: 700;
  color: var(--accent);
}

.engine-meta {
  flex: 1;
}

.engine-name {
  font-weight: 600;
  font-size: 1.125rem;
  margin-bottom: 0.125rem;
}

.engine-type {
  font-size: 0.75rem;
  color: var(--text-muted);
  font-family: var(--font-mono);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.engine-status {
  display: flex;
  align-items: center;
  gap: 0.375rem;
  font-size: 0.75rem;
  color: var(--accent);
}

.engine-status-dot {
  width: 6px;
  height: 6px;
  background: var(--accent);
  border-radius: 50%;
}

.engine-description {
  color: var(--text-secondary);
  font-size: 0.9375rem;
  line-height: 1.6;
}
</style>

<script setup lang="ts">
import { ref, onMounted } from 'vue';

interface TerminalLine {
  type: 'command' | 'output' | 'success' | 'error' | 'warning';
  text: string;
  delay?: number;
}

const lines = ref<TerminalLine[]>([]);
const showCursor = ref(true);
const isTyping = ref(false);

const terminalContent: TerminalLine[] = [
  { type: 'command', text: 'verdict scan', delay: 0 },
  { type: 'output', text: '', delay: 300 },
  { type: 'output', text: 'Security Engines Status', delay: 400 },
  { type: 'output', text: '──────────────────────────────────────────────', delay: 500 },
  { type: 'success', text: '✓ gosec         scanning...', delay: 700 },
  { type: 'success', text: '✓ govulncheck   scanning...', delay: 900 },
  { type: 'success', text: '✓ gitleaks      scanning...', delay: 1100 },
  { type: 'success', text: '✓ staticcheck   scanning...', delay: 1300 },
  { type: 'success', text: '✓ syft          generating SBOM...', delay: 1500 },
  { type: 'success', text: '✓ cyclonedx     generating SBOM...', delay: 1700 },
  { type: 'output', text: '', delay: 1900 },
  { type: 'output', text: '──────────────────────────────────────────────', delay: 2000 },
  { type: 'success', text: 'Assessment: PASS', delay: 2200 },
  { type: 'success', text: 'Findings: 0 critical, 0 high, 0 medium, 2 low', delay: 2400 },
];

onMounted(() => {
  isTyping.value = true;

  terminalContent.forEach((line, index) => {
    setTimeout(() => {
      lines.value.push(line);
      if (index === terminalContent.length - 1) {
        isTyping.value = false;
      }
    }, line.delay || 0);
  });
});
</script>

<template>
  <div class="terminal">
    <div class="terminal-header">
      <span class="terminal-dot red"></span>
      <span class="terminal-dot yellow"></span>
      <span class="terminal-dot green"></span>
      <span class="terminal-title">verdict scan</span>
    </div>
    <div class="terminal-body">
      <div v-for="(line, index) in lines" :key="index" class="terminal-line">
        <template v-if="line.type === 'command'">
          <span class="terminal-prompt">$</span>
          <span class="terminal-command">{{ line.text }}</span>
        </template>
        <template v-else>
          <span :class="['terminal-output', line.type]">{{ line.text }}</span>
        </template>
      </div>
      <div class="terminal-line" v-if="!isTyping">
        <span class="terminal-prompt">$</span>
        <span class="typing-cursor" v-if="showCursor"></span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.terminal {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: 12px;
  overflow: hidden;
  box-shadow:
    0 0 0 1px rgba(255,255,255,0.03),
    0 20px 50px -20px rgba(0,0,0,0.5),
    0 0 100px -50px var(--accent-glow);
}

.terminal-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.875rem 1rem;
  background: var(--bg-tertiary);
  border-bottom: 1px solid var(--border);
}

.terminal-dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
}

.terminal-dot.red { background: #ff5f56; }
.terminal-dot.yellow { background: #ffbd2e; }
.terminal-dot.green { background: #27c93f; }

.terminal-title {
  flex: 1;
  text-align: center;
  font-family: var(--font-mono);
  font-size: 0.75rem;
  color: var(--text-muted);
}

.terminal-body {
  padding: 1.5rem;
  font-family: var(--font-mono);
  font-size: 0.875rem;
  line-height: 1.7;
  min-height: 320px;
}

.terminal-line {
  display: flex;
  gap: 0.75rem;
  margin-bottom: 0.25rem;
}

.terminal-prompt {
  color: var(--accent);
  user-select: none;
}

.terminal-command {
  color: var(--text-primary);
}

.terminal-output {
  color: var(--text-secondary);
  padding-left: 1.5rem;
}

.terminal-output.success { color: var(--accent); }
.terminal-output.error { color: var(--danger); }
.terminal-output.warning { color: var(--warning); }

.typing-cursor {
  display: inline-block;
  width: 8px;
  height: 18px;
  background: var(--accent);
  margin-left: 2px;
  animation: blink 1s step-end infinite;
  vertical-align: middle;
}

@keyframes blink {
  50% { opacity: 0; }
}
</style>

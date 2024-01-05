<script setup lang="ts">
defineProps<{
  text: string;
  cond?: boolean;
}>();
</script>

<template>
  <label v-if="cond ?? true" absolute text-sm text-red-500 w-64 lg:w-72>
    {{ $t(text) }}
  </label>
</template>

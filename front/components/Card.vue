<script setup lang="ts">
/* eslint vue/multi-word-component-names: "off", vue/valid-attribute-name: "off" */

defineProps({
  title: {
    type: String,
    required: true,
    default: "",
  },
});
</script>

<template>
  <!-- bg-gradient-to-r from-violet-400/20 via-amber-50/20 to-zinc-50 backdrop-blur-3xl -->
  <div
    w-full
    xl:w-2xl
    mt-8
    bg-zinc-50
    dark:bg-dark
    border
    border-gray-900
    rounded-lg
  >
    <p pl-6 font-semibold text-lg>{{ $props.title }}</p>
    <slot />
  </div>
</template>

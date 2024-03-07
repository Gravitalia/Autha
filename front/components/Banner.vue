<script setup lang="ts">
const isClosed = ref(false);
</script>

<template>
  <div
    v-if="!isClosed"
    fixed
    top-0
    left-0
    right-0
    z-50
    flex
    items-center
    gap-x-6
    backdrop-blur-3xl
    px-6
    py-1
    sm:px-3.5
    sm:before:flex-1
  >
    <div
      class="absolute top-1/2 -z-10 transform-gpu blur-2xl"
      aria-hidden="true"
    >
      <div
        class="w-full bg-gradient-to-r from-violet-400 via-violet-700 to-violet-400 opacity-30"
        style="
          clip-path: polygon(
            74.8% 41.9%,
            97.2% 73.2%,
            100% 34.9%,
            92.5% 0.4%,
            87.5% 0%,
            75% 28.6%,
            58.5% 54.6%,
            50.1% 56.8%,
            46.9% 44%,
            48.3% 17.4%,
            24.7% 53.9%,
            0% 27.9%,
            11.9% 74.2%,
            24.9% 54.1%,
            68.6% 100%,
            74.8% 41.9%
          );
        "
      ></div>
    </div>
    <div xl:ml-8 flex flex-wrap items-center gap-x-4 gap-y-2>
      <p font-semibold text-sm leading-6>Avertissement</p>
      <p text-sm leading-6 text-zinc-700 dark:text-zinc-200>
        Les services de gestion de compte ne sont actuellement pas disponibles.
      </p>
    </div>
    <div xl:mr-8 flex flex-1 justify-end>
      <button
        type="button"
        @click="isClosed = true"
        cursor-pointer
        -m-3
        focus-visible:outline-offset-[-4px]
        bg-transparent
        border-none
      >
        <span sr-only>Dismiss</span>
        <svg
          h-5
          w-5
          fill-zinc-900
          dark:fill-zinc-200
          viewBox="0 0 20 20"
          aria-hidden="true"
        >
          <path
            d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z"
          />
        </svg>
      </button>
    </div>
  </div>
</template>

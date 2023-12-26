<script setup lang="ts">
import type { NuxtError } from "#app";

const { error } = defineProps<{
  error: Partial<NuxtError>;
}>();

const errorCodes: Record<number, string> = {
  404: "page_not_found",
};

/* eslint-disable no-console */
if (process.dev) console.error(error);
</script>

<template>
  <NuxtLayout>
    <template #title>
      <span timeline-title-style>Error</span>
    </template>
    <slot>
      <div h-screen font-sans flex-col container>
        <h1 text-2xl>
          {{ $t(errorCodes[error.statusCode!] || "something_went_wrong") }}
        </h1>

        <NuxtLink to="/" prefetch btn-base no-underline mt-11>{{
          $t("return_home")
        }}</NuxtLink>
      </div>
    </slot>
  </NuxtLayout>
</template>

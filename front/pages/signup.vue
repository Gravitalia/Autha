<script setup lang="ts">
import type { Error, TokenResponse } from "../types/index";

// Define reactive refs for error handling.
const isError: Record<string, Ref<boolean>> = {
  invalidEmail: ref(false),
  invalidToken: ref(false),
  invalidPassword: ref(false),
  invalidPhone: ref(false),
  tooYoung: ref(false),
  rateLimited: ref(false),
  internalServerError: ref(false),
};

// Define reactive refs for user input.
const token = ref();
const email = ref("");
const password = ref("");
const birthdate = ref("");
const phone = ref("");

// Internal variables.
const step = ref(0);

// Redirect if user is already connected.
if (useCookie("session").value !== "") {
  const user = useUser();
  user.fetchUser();

  if (user.vanity !== "") await navigateTo("/");
}

function next(): void {
  ++step.value;
}

async function signup(): Promise<void> {
  // Set all errors to false before processing the sign-in.
  for (const key in isError) {
    isError[key].value = false;
  }
}
</script>

<template>
  <!-- Cloudflare Turnstile implementation. -->
  <NuxtTurnstile v-model="token" />

  <!-- Blurry effect in background. -->
  <div absolute flex justify-between w-98vw>
    <div
      rounded-full
      w-48
      h-48
      xl:w-80
      xl:h-80
      blur-5xl
      mt-80
      xl:mt-30rem
      bg-primary
    ></div>
    <div rounded-full w-48 h-48 xl:w-80 xl:h-80 blur-5xl bg-secondary></div>
  </div>

  <!-- Centered card containing inputs to connect. -->
  <div absolute w-96vw h-98vh container>
    <div
      bg-zinc-50
      dark:bg-dark
      border
      border-gray-900
      w-80
      h-80
      lg:w-96
      lg:h-96
      shadow-lg
    >
      <div mt-4 lg:mt-8 mb-4 lg:mb-8 flex-col container>
        <NuxtImg
          alt="Gravitalia"
          src="/favicon.webp"
          width="40"
          draggable="false"
        />
        <h3 font-semibold>{{ $t("Create an account") }}</h3>
      </div>

      <div flex-col container>
        <!-- Generic errors. -->
        <label
          v-if="isError.invalidToken.value"
          mb-34
          absolute
          text-sm
          text-red-500
          w-64
        >
          {{ $t("Invalid security token, try again in a few seconds.") }}
        </label>

        <label
          v-if="isError.rateLimited.value"
          mb-34
          absolute
          text-sm
          text-red-500
          w-64
        >
          {{ $t("You're sending too many requests! Try again in 5 minutes.") }}
        </label>

        <label
          v-if="isError.internalServerError.value"
          mb-34
          absolute
          text-sm
          text-red-500
          w-64
        >
          {{ $t("Something went wrong") }}
        </label>

        <!-- input. -->
      </div>

      <!-- Links and buttons. -->
      <div flex container>
        <div flex justify-between w-16.5rem mt-8>
          <!-- Buttons on the left. -->
          <NuxtLink v-if="step === 0" to="/signin" btn-invisible no-underline>{{
            $t("Sign in")
          }}</NuxtLink>
          <button
            v-else
            font-sans
            font-medium
            btn-invisible
            bg-transparent
            type="button"
            @click="--step"
          >
            {{ $t("Previous") }}
          </button>

          <!-- Buttons on the right. -->
          <button
            v-if="step === 0"
            font-sans
            font-medium
            btn-base
            type="button"
            @click="next()"
          >
            {{ $t("Next") }}
          </button>
          <button
            v-else
            font-sans
            font-medium
            btn-base
            type="button"
            @click="signup()"
          >
            {{ $t("Create an account") }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

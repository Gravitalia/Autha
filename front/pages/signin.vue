<script setup lang="ts">
import type { Error, TokenResponse } from "../types/index";

// Define reactive refs for error handling.
const isError: Record<string, Ref<boolean>> = {
  invalidEmail: ref(false),
  invalidToken: ref(false),
  invalidPassword: ref(false),
  missingEmail: ref(false),
  missingPassword: ref(false),
  rateLimited: ref(false),
  internalServerError: ref(false),
};

// Define reactive refs for user input.
const token = ref();
const email = ref("");
const password = ref("");

// Redirect if user is already connected.
if (useCookie("session").value !== "") {
  const user = useUser();
  user.fetchUser();

  if (user.vanity !== "") await navigateTo("/");
}

async function signin(): Promise<void> {
  // Set all errors to false before processing the sign-in.
  for (const key in isError) {
    isError[key].value = false;
  }

  // Check for missing values in the user input.
  if (email.value === "") {
    isError.missingEmail.value = true;
    return;
  } else if (password.value === "") {
    isError.missingPassword.value = true;
    return;
  }

  // Create headers.
  const headers: Headers = new Headers();
  headers.append("Content-Type", "application/json");
  headers.append("CF-Turnstile-Token", token.value);

  // Make request.
  const json: Error | TokenResponse = await fetch(
    useRuntimeConfig().public.API_URL + "/login",
    {
      method: "post",
      headers,
      body: JSON.stringify({
        email: email.value,
        password: password.value,
      }),
    },
  )
    .then((response) => response.json())
    .catch((_) => (isError.internalServerError.value = true));

  // Handle error process.
  if ("error" in json) {
    if (json.message === "Invalid turnstile token")
      isError.invalidToken.value = true;
    else if (json.message === "Invalid email")
      isError.invalidEmail.value = true;
    else if (json.message === "Invalid password")
      isError.invalidPassword.value = true;
    else if (json.message === "You are being rate limited.")
      isError.rateLimited.value = true;
    else {
      /* eslint-disable no-console */
      console.error(json.message);
      isError.internalServerError.value = true;
    }

    // Re-create Turnstile token.
    token.value?.reset();
  } else {
    useCookie("session", {
      maxAge: 1200000, // Around two weeks.
      sameSite: "strict",
      secure: true,
    }).value = json.token;

    useI18n().setLocale(json.user_settings.locale);

    await navigateTo("/");
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
        <h3 font-semibold>{{ $t("Sign in") }}</h3>
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

        <!-- Email input. -->
        <label
          v-if="isError.missingEmail.value"
          mb-28
          absolute
          text-sm
          text-red-500
          w-64
        >
          {{ $t("Write something...") }}
        </label>

        <label
          v-if="isError.invalidEmail.value"
          mb-28
          absolute
          text-sm
          text-red-500
          w-64
        >
          {{ $t("Invalid email address") }}
        </label>

        <input
          v-model="email"
          :class="
            isError.invalidEmail.value || isError.missingEmail.value
              ? 'border-red-500 dark:border-red-500'
              : ''
          "
          input
          mb-6
          lg:mb-8
          type="email"
          :placeholder="$t('Email address')"
        />

        <!-- Password input. -->
        <label
          v-if="isError.missingPassword.value"
          mt-4
          absolute
          text-sm
          text-red-500
          w-64
        >
          {{ $t("Write down your secret word 🤫") }}
        </label>

        <label
          v-if="isError.invalidPassword.value"
          mt-4
          absolute
          text-sm
          text-red-500
          w-64
        >
          {{ $t("Invalid password") }}
        </label>

        <input
          v-model="password"
          :class="
            isError.invalidPassword.value || isError.missingPassword.value
              ? 'border-red-500 dark:border-red-500'
              : ''
          "
          input
          type="password"
          :placeholder="$t('Password')"
        />
      </div>

      <!-- Links and buttons. -->
      <div flex container>
        <div flex justify-between w-16.5rem mt-8>
          <NuxtLink to="/signup" btn-invisible no-underline>{{
            $t("Create an account")
          }}</NuxtLink>
          <button
            font-sans
            font-medium
            btn-base
            type="button"
            @click="signin()"
          >
            {{ $t("Sign in") }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

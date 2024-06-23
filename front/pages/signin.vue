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
const isButtonDisable = ref(false);

// Redirect if user is already connected.
if (useCookie("session").value !== "") {
  const user = useUser();
  user.fetchUser();

  if (user.vanity !== "") await navigateTo("/");
}

async function signin() {
  // Disable button until the end.
  isButtonDisable.value = true;

  // Set all errors to false before processing the sign-in.
  for (const key in Object.keys(isError)) {
    isError[key].value = false;
  }

  // Check for missing values in the user input.
  if (email.value === "") {
    isError.missingEmail.value = true;
    isButtonDisable.value = false;
    return;
  } else if (password.value === "") {
    isError.missingPassword.value = true;
    isButtonDisable.value = false;
    return;
  }

  // Create headers.
  const headers: Headers = new Headers();
  headers.append("Content-Type", "application/json");
  headers.append("CF-Turnstile-Token", token.value);

  // Make request.
  const json: Error | TokenResponse = await fetch(
    `${useRuntimeConfig().public.API_URL}/login`,
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

  // Re-activate button.
  isButtonDisable.value = false;

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
  <FontBubbles />

  <!-- Banner prevention. -->
  <Banner :content="$t('services_unavailable')" :can-close="false" />

  <!-- Centered card containing inputs to connect. -->
  <div absolute w-96vw h-98vh container>
    <div
      class="bg-zinc-50 dark:bg-dark border border-gray-900 w-80 h-80 lg:w-96 lg:h-96 2xl:w-26rem 2xl:h-26rem shadow-lg"
    >
      <div mt-6 lg:mt-10 mb-8 lg:mb-10 divide-x space-x-2 container>
        <NuxtImg
          alt="Gravitalia"
          src="/favicon.webp"
          width="35"
          height="35"
          draggable="false"
        />

        <div class="h-1.5rem bg-zinc-400 w-0.1rem"></div>

        <h3 font-semibold>{{ $t("sign_in") }}</h3>
      </div>

      <div flex-col container>
        <!-- Generic errors. -->
        <LabelError
          v-if="isError.invalidToken.value"
          mb-42
          text="error.security_token"
        />
        <LabelError
          v-if="isError.rateLimited.value"
          mb-42
          text="error.rate_limit"
        />
        <LabelError
          v-if="isError.internalServerError.value"
          mb-42
          text="something_went_wrong"
        />

        <!-- Email input. -->
        <LabelError
          v-if="isError.missingEmail.value"
          mb-36
          text="error.write_something"
        />
        <LabelError
          v-if="isError.invalidEmail.value"
          mb-36
          text="error.invalid_email"
        />

        <input
          v-model="email"
          :class="
            isError.invalidEmail.value || isError.missingEmail.value
              ? 'border-red-500 dark:border-red-500'
              : ''
          "
          input
          mb-8
          lg:mb-10
          type="email"
          :placeholder="$t('email')"
        />

        <!-- Password input. -->
        <LabelError
          v-if="isError.missingPassword.value"
          text="error.missing_password"
        />
        <LabelError
          v-if="isError.invalidPassword.value"
          text="error.invalid_password"
        />

        <input
          v-model="password"
          :class="
            isError.invalidPassword.value || isError.missingPassword.value
              ? 'border-red-500 dark:border-red-500'
              : ''
          "
          input
          type="password"
          :placeholder="$t('password')"
        />

        <!-- No more access. -->
        <div hidden lg:block mt-2 w-64 lg:w-72>
          <NuxtLink
            :to="'mailto:' + useRuntimeConfig().email"
            text-sm
            text-link
          >
            {{ $t("lost_account") }}
          </NuxtLink>
        </div>
      </div>

      <!-- Links and buttons. -->
      <div flex container>
        <div flex justify-between w-16.5rem lg:w-18.5rem mt-11>
          <NuxtLink to="/signup" btn-invisible no-underline>{{
            $t("create_account")
          }}</NuxtLink>
          <button
            font-sans
            font-medium
            btn-base
            type="button"
            :disabled="isButtonDisable"
            @click="signin()"
          >
            {{ $t("sign_in") }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

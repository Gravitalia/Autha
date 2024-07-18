<script setup lang="ts">
import type { Error, TokenResponse } from "../types/index";

// Define reactive refs for error handling.
const isError: Record<string, Ref<boolean>> = {
  invalidToken: ref(false),
  invalidPassword: ref(false),
  missingPassword: ref(false),
  rateLimited: ref(false),
  internalServerError: ref(false),
};

// Define reactive refs for user input.
const token = ref();
const password = ref("");
const isButtonDisable = ref(false);

const user = useUser();
user.fetchUser();

// Redirect to the login page if user is not connected.
if (useCookie("session").value === "" || user.vanity === "")
  await navigateTo("/signin");

// Redirect if user have already a password.
if (typeof user.password === "string" && user.password.length !== 0)
  await navigateTo("/security");

async function signin() {
  // Disable button until the end.
  isButtonDisable.value = true;

  // Set all errors to false before processing the sign-in.
  for (const key in isError) {
    isError[key].value = false;
  }

  // Check if password is missing.
  if (password.value === "") {
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
        email: user.email,
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

    user.password = password.value;

    await navigateTo("/security");
  }
}
</script>

<template>
  <!-- Cloudflare Turnstile implementation. -->
  <NuxtTurnstile v-model="token" />

  <!-- Blurry effect in background. -->
  <FontBubbles />

  <!-- Banner prevention. -->
  <Banner :content="$t('access.warn')" :can-close="false" />

  <!-- Centered card containing inputs to connect. -->
  <div absolute w-96vw h-98vh flex-col container space-y-6>
    <div
      class="bg-zinc-50 dark:bg-dark border border-gray-900 w-80 h-18 lg:w-96 container"
    >
      <p>{{ $t("logged_as", { vanity: user.vanity }) }}</p>
    </div>

    <div
      class="bg-zinc-50 dark:bg-dark border border-gray-900 w-80 h-80 lg:w-96 shadow-lg"
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

        <h3 font-semibold>{{ $t("access.title") }}</h3>
      </div>

      <div flex-col container>
        <!-- Errors. -->
        <LabelError
          v-if="isError.invalidToken.value"
          mb-26
          text="error.security_token"
        />
        <LabelError
          v-if="isError.rateLimited.value"
          mb-26
          text="error.rate_limit"
        />
        <LabelError
          v-if="isError.internalServerError.value"
          mb-26
          text="something_went_wrong"
        />
        <LabelError
          v-if="isError.missingPassword.value"
          mb-26
          text="error.missing_password"
        />
        <LabelError
          v-if="isError.invalidPassword.value"
          mb-26
          text="error.invalid_password"
        />

        <!-- Password input. -->
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
        <div mt-2 w-64 lg:w-72>
          <NuxtLink
            :to="'mailto:' + useRuntimeConfig().email"
            text-sm
            text-link
          >
            {{ $t("lost_account") }}
          </NuxtLink>
        </div>
      </div>

      <!-- Confirmation button. -->
      <div flex container>
        <div w-16.5rem lg:w-18.5rem mt-11>
          <button
            font-sans
            font-medium
            btn-base
            w-full
            type="button"
            :disabled="isButtonDisable"
            @click="signin()"
          >
            {{ $t("confirm") }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

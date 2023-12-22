<script setup lang="ts">
import type { Error, TokenResponse } from "../types/index";

// Define reactive refs for error handling.
const isError: Record<string, Ref<boolean>> = {
  invalidEmail: ref(false),
  invalidToken: ref(false),
  invalidPassword: ref(false),
  invalidPhone: ref(false),
  invalidVanity: ref(false),
  tooYoung: ref(false),
  rateLimited: ref(false),
  internalServerError: ref(false),
  alreadyUsedEmail: ref(false),
  missingEmail: ref(false),
  missingPassword: ref(false),
  missingFirstname: ref(false),
};

// Define reactive refs for user input.
const token = ref();
const firstname = ref("");
const lastname = ref("");
const email = ref("");
const password = ref("");
const vanity = ref("");
const birthdate: Ref<null | string> = ref(null);
const phone: Ref<null | string> = ref(null);

// Internal variables.
const step = ref(0);
const isButtonDisable = ref(false);
const locale = useI18n().locale.value;

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

  // Check for missing values in the user input.
  if (firstname.value === "") {
    isError.missingFirstname.value = true;
    if (step.value === 1) --step.value;
    isButtonDisable.value = false;
    return;
  } else if (email.value === "") {
    isError.missingEmail.value = true;
    if (step.value === 1) --step.value;
    isButtonDisable.value = false;
    return;
  } else if (password.value === "") {
    isError.missingPassword.value = true;
    if (step.value === 1) --step.value;
    isButtonDisable.value = false;
    return;
  } else if (vanity.value === "") {
    isError.invalidVanity.value = true;
    if (step.value === 0) ++step.value;
    isButtonDisable.value = false;
    return;
  }

  // Create headers.
  const headers: Headers = new Headers();
  headers.append("Content-Type", "application/json");
  headers.append("CF-Turnstile-Token", token.value);

  // Make request.
  const json: Error | TokenResponse = await fetch(
    useRuntimeConfig().public.API_URL + "/create",
    {
      method: "post",
      headers,
      body: JSON.stringify({
        username: `${firstname.value}${
          lastname.value.length !== 0 ? ` ${lastname.value}` : ""
        }`,
        vanity: vanity.value,
        email: email.value,
        password: password.value,
        locale,
        birthdate: birthdate.value,
        phone: phone.value,
      }),
    },
  )
    .then((response) => response.json())
    .catch((_) => (isError.internalServerError.value = true));

  // Re-activate button.
  isButtonDisable.value = false;

  // Handle error process.
  if ("error" in json) {
    switch (json.message) {
      case "Invalid turnstile token":
        isError.invalidToken.value = true;
        break;
      case "You are being rate limited.":
        isError.rateLimited.value = true;
        break;
      case "Invalid email":
        isError.invalidEmail.value = true;
        if (step.value === 1) --step.value;
        break;
      case "Invalid password":
        isError.invalidPassword.value = true;
        if (step.value === 1) --step.value;
        break;
      case "Invalid vanity":
      case "Vanity already used":
        isError.invalidVanity.value = true;
        if (step.value === 0) ++step.value;
        break;
      case "Invalid username":
        isError.missingFirstname.value = true;
        if (step.value === 1) --step.value;
        break;
      case "Email already used":
        isError.alreadyUsedEmail.value = true;
        if (step.value === 1) --step.value;
        break;
      default:
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

  <!-- Centered card containing inputs to connect. -->
  <div absolute w-96vw h-98vh container>
    <div
      bg-zinc-50
      dark:bg-dark
      border
      border-gray-900
      w-22rem
      h-22rem
      lg:w-96
      lg:h-96
      shadow-lg
    >
      <div mt-6 mb-4 flex-col container>
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
        <LabelError
          mb-36
          text="Invalid security token, try again in a few seconds."
          :cond="isError.invalidToken.value"
        />
        <LabelError
          mb-36
          text="You're sending too many requests! Try again in 5 minutes."
          :cond="isError.rateLimited.value"
        />

        <!-- Firstname error. -->
        <LabelError
          mb-36
          text="At least add your first name here"
          :cond="isError.missingFirstname.value"
        />

        <!-- Email errors. -->
        <LabelError
          mb-36
          text="You must enter an e-mail address!"
          :cond="isError.missingEmail.value"
        />
        <LabelError
          mb-36
          text="Email adress already used"
          :cond="isError.alreadyUsedEmail.value"
        />

        <!-- Password errors. -->
        <LabelError
          mb-36
          text="A little one-time password wouldn't hurt"
          :cond="isError.missingPassword.value"
        />
        <LabelError
          mb-36
          text="Use 8 uppercase and lowercase letters with special characters"
          :cond="isError.invalidPassword.value"
        />

        <!-- Vanity errors. -->
        <LabelError
          mb-36
          text="Your username is already in use"
          :cond="isError.invalidVanity.value"
        />
        <LabelError
          mb-36
          text="You must be at least 13 years old"
          :cond="isError.tooYoung.value"
        />

        <!-- 1-step account creation. -->
        <div v-if="step === 0">
          <!-- Firstname and name inputs. -->
          <div flex space-x-2>
            <input
              v-model="firstname"
              input
              mb-2
              lg:mb-4
              w-7.65rem
              type="text"
              maxlength="10"
              :placeholder="$t('Firstname')"
            />

            <input
              v-model="lastname"
              input
              w-7.65rem
              type="text"
              maxlength="15"
              :placeholder="$t('Lastname')"
            />
          </div>

          <!-- Email input. -->
          <div flex-col container>
            <input
              v-model="email"
              input
              mb-2
              lg:mb-4
              type="email"
              :placeholder="$t('Email address')"
            />

            <!-- Password input. -->
            <input
              v-model="password"
              input
              type="password"
              :placeholder="$t('Password')"
            />
          </div>
        </div>

        <!-- 2nd step account creation. -->
        <div v-else flex-col container>
          <div mb-2 lg:mb-4 mr-2 flex>
            <span rounded flex justify-center items-center text-sm font-mono>
              gravitalia.com/
            </span>
            <input
              v-model="vanity"
              w-8.35rem
              input
              type="text"
              maxlength="15"
              minlength="2"
              :placeholder="$t('Username').toLowerCase()"
            />
          </div>

          <input
            v-model="phone"
            input
            type="tel"
            mb-2
            lg:mb-4
            :placeholder="$t('Phone (optional)')"
          />

          <input v-model="birthdate" input type="date" />

          <!-- Terms of Service and Privacy Policy acceptance. -->
          <p w-64 mt-44 text-xs absolute>
            {{ $t("You accept our") }}
            <NuxtLink to="/terms" text-blue-500 hover:text-blue-700>{{
              $t("ToS")
            }}</NuxtLink>
            {{ $t("and our") }}
            <NuxtLink to="/privacy" text-blue-500 hover:text-blue-700>{{
              $t("privacy policy")
            }}</NuxtLink
            >.
          </p>
        </div>
      </div>

      <!-- Links and buttons. -->
      <div flex container>
        <div flex justify-between w-16.5rem mt-10>
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
            :disabled="isButtonDisable"
            @click="signup()"
          >
            {{ $t("Create an account") }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

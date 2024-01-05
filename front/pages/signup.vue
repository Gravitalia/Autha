<script setup lang="ts">
import type { Error, TokenResponse } from "../types/index";

// Define reactive refs for error handling.
const isError: Record<string, Ref<boolean>> = {
  invalidEmail: ref(false),
  invalidToken: ref(false),
  invalidPassword: ref(false),
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

async function signup() {
  // Set all errors to false before processing the sign-in.
  for (const key in isError) {
    isError[key].value = false;
  }

  // Check for missing values in the user input.
  if (firstname.value === "") {
    isError.missingFirstname.value = true;
    step.value = 0;
    isButtonDisable.value = false;
    return;
  } else if (email.value === "") {
    isError.missingEmail.value = true;
    step.value = 0;
    isButtonDisable.value = false;
    return;
  } else if (vanity.value === "") {
    isError.invalidVanity.value = true;
    step.value = 2;
    isButtonDisable.value = false;
    return;
  } else if (password.value === "") {
    isError.missingPassword.value = true;
    step.value = 2;
    isButtonDisable.value = false;
    return;
  }

  // Create headers.
  const headers: Headers = new Headers();
  headers.append("Content-Type", "application/json");
  headers.append("CF-Turnstile-Token", token.value);

  // Make request.
  const json: Error | TokenResponse = await fetch(
    `${useRuntimeConfig().public.API_URL}/create`,
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
        step.value = 0;
        break;
      case "Invalid password":
        isError.invalidPassword.value = true;
        step.value = 2;
        break;
      case "Invalid vanity":
      case "Vanity already used":
        isError.invalidVanity.value = true;
        step.value = 2;
        break;
      case "Invalid username":
        isError.missingFirstname.value = true;
        step.value = 0;
        break;
      case "Email already used":
        isError.alreadyUsedEmail.value = true;
        step.value = 0;
        break;
      case "Too young":
        isError.tooYoung.value = true;
        step.value = 1;
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
  <div absolute w-96vw h-98vh container flex-col>
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

        <h3 v-if="step === 0" font-semibold>{{ $t("create_account") }}</h3>
        <h3 v-else-if="step === 1" font-semibold>
          {{ $t("optional_information") }}
        </h3>
        <h3 v-else-if="step === 2" font-semibold>
          {{ $t("required_information") }}
        </h3>
      </div>

      <div flex-col container>
        <!-- Generic errors. -->
        <LabelError
          mb-34
          text="error.security_token"
          :cond="isError.invalidToken.value"
        />
        <LabelError
          mb-34
          text="error.rate_limit"
          :cond="isError.rateLimited.value"
        />
        <LabelError
          mb-34
          text="something_went_wrong"
          :cond="isError.internalServerError.value"
        />

        <!-- 1-step account creation. -->
        <div v-if="step === 0" flex-col container>
          <!-- Firstname error. -->
          <LabelError
            mb-30
            text="error.missing_firstname"
            :cond="isError.missingFirstname.value"
          />

          <!-- Firstname and name inputs. -->
          <div flex space-x-2 mb-8 lg:mb-10>
            <input
              v-model="firstname"
              input
              w-7.65rem
              lg:w-8.65rem
              type="text"
              maxlength="10"
              :placeholder="$t('firstname')"
            />

            <input
              v-model="lastname"
              input
              w-7.65rem
              lg:w-8.65rem
              type="text"
              maxlength="15"
              :placeholder="$t('lastname')"
            />
          </div>

          <!-- Email errors. -->
          <LabelError
            mt-4
            text="error.missing_email"
            :cond="isError.missingEmail.value"
          />
          <LabelError
            mt-4
            text="error.email_used"
            :cond="isError.alreadyUsedEmail.value"
          />

          <!-- Email input. -->
          <div flex-col container>
            <input
              v-model="email"
              input
              type="email"
              :placeholder="$t('email')"
            />
          </div>
        </div>

        <!-- 2nd step account creation. -->
        <div v-else-if="step === 1" flex-col container>
          <!-- Phone number input. -->
          <input
            v-model="phone"
            input
            type="tel"
            mb-8
            lg:mb-10
            :placeholder="$t('phone')"
          />

          <!-- Birthdate error. -->
          <LabelError
            mt-4
            text="error.too_young"
            :cond="isError.tooYoung.value"
          />

          <!-- Birthdate input. -->
          <input v-model="birthdate" input type="date" />
        </div>

        <!-- 3rd step account creation. -->
        <div v-else-if="step === 2" flex-col container>
          <!-- Vanity errors. -->
          <LabelError
            mb-30
            text="error.vanity_used"
            :cond="isError.invalidVanity.value"
          />

          <!-- Vanity input. -->
          <div mb-8 lg:mb-10 mr-2 flex>
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
              :placeholder="$t('username').toLowerCase()"
            />
          </div>

          <!-- Password errors. -->
          <LabelError
            mt-4
            text="error.missing_password_sign_up"
            :cond="isError.missingPassword.value"
          />
          <LabelError
            mt-4
            text="error.password_advices"
            :cond="isError.invalidPassword.value"
          />

          <!-- Password input. -->
          <input
            v-model="password"
            input
            type="password"
            :placeholder="$t('password')"
          />
        </div>
      </div>

      <!-- Links and buttons. -->
      <div flex container>
        <div flex justify-between w-16.5rem lg:w-18.5rem mt-10 lg:mt-12>
          <!-- Buttons on the left. -->
          <NuxtLink v-if="step === 0" to="/signin" btn-invisible no-underline>{{
            $t("sign_in")
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
            {{ $t("previous") }}
          </button>

          <!-- Buttons on the right. -->
          <button
            v-if="step < 2"
            font-sans
            font-medium
            btn-base
            type="button"
            @click="++step"
          >
            {{ $t("next") }}
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
            {{ $t("create_account") }}
          </button>
        </div>
      </div>
    </div>

    <!-- Terms of Service and Privacy Policy acceptance. -->
    <p v-if="step === 2" mt-96 lg:mt-28rem absolute text-xs>
      {{ $t("accept_our") }}
      <NuxtLink to="/terms" target="_blank" text-blue-500 hover:text-blue-700>{{
        $t("tos")
      }}</NuxtLink>
      {{ $t("and_our") }}
      <NuxtLink to="/privacy" target="_blank" text-blue-500 hover:text-blue-700>
        {{ $t("privacy_policy") }} </NuxtLink
      >.
    </p>
  </div>
</template>

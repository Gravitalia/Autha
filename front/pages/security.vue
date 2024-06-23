<script setup lang="ts">
import { useUser } from "../stores/user";
import type { Error } from "../types/index";

const user = useUser();
user.fetchUser();

// Redirect to the login page if user is not connected.
if (useCookie("session").value === "" || user.vanity === "")
  await navigateTo("/signin");

// Redirect to the security access page if user have not entered password.
if (typeof user.password !== "string" || user.password.length === 0)
  await navigateTo("/access");

// Modal manager.
const modals: Record<string, Ref<boolean>> = {
  email: ref(false),
  password: ref(false),
};

// Modal data.
const password = ref("");
const email = ref("");
const loadingButton = ref(false);

// Error.
const serverError = ref(false);

async function update() {
  loadingButton.value = true;

  // Create headers.
  const headers: Headers = new Headers();
  headers.append("Content-Type", "application/json");
  headers.append("Authorization", useCookie("session").value as string);

  // Create body.
  const body: { [id: string]: string | number[] } = {};
  body.password = user.password as string;

  await fetch(
    `${
      useRuntimeConfig().public?.API_URL ?? "https://oauth.gravitalia.com"
    }/users/@me`,
    {
      method: "PATCH",
      headers,
      body: JSON.stringify(body),
    },
  )
    .then((response) => response.json())
    .then((json: Error) => {
      if (!json.error) {
        for (const key of Object.keys(modals)) {
          modals[key].value = false;
        }
      }
    })
    .catch((_) => (serverError.value = true));

  loadingButton.value = false;
}
</script>

<template>
  <SideBar />

  <div p-6 sm:ml-64>
    <div
      p-3
      xl:px-16
      border-2
      lg:h-90vh
      border-gray-200
      border-dashed
      rounded-lg
      dark:border-gray-700
    >
      <h1>{{ $t("security.title") }}</h1>
      <p text-zinc-700 mb-3>
        {{ $t("security.description") }}
      </p>

      <div w-full justify-between grid grid-cols-1 xl:grid-cols-2>
        <Card :title="$t('connection')">
          <div py-8 px-6 xl:px-32>
            <div bg-white rounded>
              <!-- Update email. -->
              <div
                p-2
                bg-white
                hover:bg-zinc-100
                flex
                justify-between
                cursor-pointer
                @click="
                  serverError = false;
                  modals.email.value = true;
                "
              >
                {{ $t("email") }}
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke-width="1.5"
                  stroke="currentColor"
                  w-6
                  h-6
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    d="m8.25 4.5 7.5 7.5-7.5 7.5"
                  />
                </svg>
              </div>
              <!-- Update password. -->
              <div
                p-2
                bg-white
                hover:bg-zinc-100
                flex
                justify-between
                cursor-pointer
                @click="
                  serverError = false;
                  modals.password.value = true;
                "
              >
                {{ $t("password") }}
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke-width="1.5"
                  stroke="currentColor"
                  w-6
                  h-6
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    d="m8.25 4.5 7.5 7.5-7.5 7.5"
                  />
                </svg>
              </div>
            </div>
          </div>
        </Card>

        <Card :title="$t('mfa')">
          <div py-8 px-6 xl:px-32>
            <p text-zinc-700>{{ $t("mfa_soon") }}</p>
          </div>
        </Card>
      </div>
    </div>
  </div>

  <UpdateModal
    v-if="modals.email.value"
    :title="$t('update.email.title')"
    :actual-data="user.email as string"
    @close="
      modals.email.value = false;
      email = '';
    "
  >
    <LabelError v-if="serverError" relative text="something_went_wrong" />
    <input
      v-model="email"
      input
      w-full
      :placeholder="$t('email')"
      type="email"
      minlength="8"
      maxlength="32"
    />

    <button
      type="button"
      :disabled="loadingButton || email === user.email"
      mt-6
      btn-base
      w-full
      @click="update"
    >
      {{ $t("save") }}
    </button>
  </UpdateModal>

  <UpdateModal
    v-if="modals.password.value"
    :title="$t('update.password.title')"
    @close="
      modals.password.value = false;
      password = '';
    "
  >
    <LabelError v-if="serverError" relative text="something_went_wrong" />
    <input
      v-model="password"
      input
      w-full
      :placeholder="$t('password')"
      type="password"
      minlength="8"
      maxlength="32"
    />

    <button
      type="button"
      :disabled="loadingButton || password.length < 8 || password.length > 32"
      mt-6
      btn-base
      w-full
      @click="update"
    >
      {{ $t("save") }}
    </button>
  </UpdateModal>
</template>

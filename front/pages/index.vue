<script setup lang="ts">
import { useUser } from "../stores/user";
import type { Error } from "../types/index";

const user = useUser();
user.fetchUser();

// Redirect if user is not connected to the login page.
if (useCookie("session").value === "" || user.vanity === "")
  await navigateTo("/signin");

// Modal manager.
const openedModals: Record<string, Ref<boolean>> = {
  name: ref(false),
  avatar: ref(false),
};

// Modal data.
const name = ref(user.username);
const avatar = ref();
const loadingButton = ref(false);

// From VDOM.
const avatarInput = ref();
const canvas = ref();
onMounted(() => {
  if (
    (!user.avatar || user.avatar?.length === 0) &&
    canvas.value !== undefined
  ) {
    const fontColors = useRuntimeConfig().public.AVATAR_COLORS;
    const acronym = user.username ? user.username.split("")[0] : "A";
    const acronymOrder =
      acronym.toLowerCase().charCodeAt(0) - "a".charCodeAt(0) + 1;

    const ctx = canvas.value.getContext("2d");
    ctx.font = "90px Arial";
    ctx.fillStyle = fontColors[acronymOrder % fontColors.length];
    ctx.fillRect(0, 0, canvas.value.width, canvas.value.height);
    ctx.textAlign = "center";
    ctx.fillStyle = "white";
    ctx.fillText(acronym, 75, 105);
  }

  avatarInput.value.addEventListener("change", (event: Event) => {
    const selectedFiles = (event.target as HTMLInputElement).files;

    if (selectedFiles && selectedFiles.length > 0) {
      const file = selectedFiles[0];
      if (file.type.startsWith("image/")) {
        const reader = new FileReader();

        reader.onload = (event) => {
          avatar.value = event.target?.result;
        };

        reader.readAsDataURL(file);
      }
    }
  });
});

async function update() {
  loadingButton.value = true;

  // Create headers.
  const headers: Headers = new Headers();
  headers.append("Content-Type", "application/json");
  headers.append("Authorization", useCookie("session").value as string);

  // Create body.
  const body: { [id: string]: string | number[] } = {};
  if (name.value !== user.username) body.username = name.value;
  if (avatar.value !== null)
    body.avatar = Array.from(
      new Uint8Array(await (await fetch(avatar.value)).arrayBuffer()),
    );

  const json: Error = await fetch(
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
    .catch((_) => (loadingButton.value = false));

  loadingButton.value = false;

  if (!json.error) {
    window.location.reload();
  }
}
</script>

<template>
  <SideBar />

  <div p-6 sm:ml-64>
    <div
      p-3
      xl:px-16
      border-2
      h-85vh
      xl:h-90vh
      border-gray-200
      border-dashed
      rounded-lg
      dark:border-gray-700
    >
      <h1>{{ $t("about.title") }}</h1>
      <p text-zinc-700 mb-3>
        {{ $t("about.description") }}
      </p>

      <!-- bg-gradient-to-r  from-violet-400/20 via-amber-50/20 to-zinc-50 backdrop-blur-3xl -->
      <div w-full flex justify-between grid grid-cols-1 xl:grid-cols-2>
        <div w-2xl mt-8 bg-zinc-50 border border-gray-900 rounded-lg>
          <p pl-6 font-semibold text-lg>{{ $t("about.public_profile") }}</p>
          <div flex flex-col space-y-3 justify-center items-center>
            <NuxtImg
              v-if="user.avatar && user.avatar.length !== 0"
              rounded-full
              w-24
              h-24
              :src="
                useRuntimeConfig().public.CDN_URL +
                '/t_avatar/' +
                user.avatar +
                '.webp'
              "
            />
            <canvas
              v-else
              ref="canvas"
              width="150px"
              height="150px"
              rounded-full
              w-24
              h-24
            ></canvas>

            <div v-if="user.username.length === 0" animate-pulse>
              <div h-3 bg-zinc-300 rounded-full dark:bg-zinc-700 w-26></div>
              <span sr-only>{{ $t("screen_reader.loading") }}</span>
            </div>
            <span v-else font-semibold>{{ user.username }}</span>
          </div>

          <div py-8 px-32>
            <div bg-white rounded>
              <!-- Update username. -->
              <div
                p-2
                bg-white
                hover:bg-zinc-100
                flex
                justify-between
                cursor-pointer
                @click="openedModals.name.value = true"
              >
                {{ $t("username") }}
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
              <!-- Update profile picture. -->
              <div
                p-2
                bg-white
                hover:bg-zinc-100
                flex
                justify-between
                cursor-pointer
                @click="openedModals.avatar.value = true"
              >
                {{ $t("profile_picture") }}
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
        </div>

        <!--
          <div
            class="w-full max-w-xl 2xl:max-w-2xl mt-8 bg-zinc-50 dark:bg-dark border border-gray-900 rounded-lg"
          >
            <p pl-6 font-semibold text-lg>
              {{ $t("about.personal_information") }}
            </p>
          </div>
        -->
      </div>
    </div>
  </div>

  <UpdateModal
    v-if="openedModals.name.value"
    :actual-data="name"
    :title="$t('update.username.title')"
    :description="$t('update.username.description')"
    @close="
      openedModals.name.value = false;
      name = user.username;
    "
  >
    <input
      v-model="name"
      input
      w-full
      :placeholder="$t('username.title')"
      minlength="1"
      maxlength="25"
    />

    <button
      type="button"
      :disabled="loadingButton || user.username === name"
      mt-6
      btn-base
      w-full
      @click="update"
    >
      {{ $t("save") }}
    </button>
  </UpdateModal>
  <input
    ref="avatarInput"
    type="file"
    accept="image/png,image/jpeg,image/webp"
    hidden
  />
  <UpdateModal
    v-if="openedModals.avatar.value"
    :actual-data="name"
    :title="$t('update.profile_picture.title')"
    @close="
      openedModals.avatar.value = false;
      avatar = null;
    "
  >
    <div flex flex-col items-center>
      <NuxtImg
        rounded-full
        w-24
        h-24
        :src="
          avatar ??
          (user.avatar && user.avatar.length !== 0
            ? useRuntimeConfig().public.CDN_URL +
              '/t_avatar/' +
              user.avatar +
              '.webp'
            : canvas.toDataURL())
        "
        draggable="false"
      />

      <button
        type="button"
        :disabled="loadingButton"
        mt-12
        flex
        items-center
        justify-center
        btn-base
        w-full
        @click="avatar ? update() : avatarInput.click()"
      >
        <template v-if="avatar">
          {{ $t("save") }}
        </template>
        <template v-else>
          <svg
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
            stroke-width="1.5"
            stroke="currentColor"
            w-5
            h-5
            px-2
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              d="M19.5 14.25v-2.625a3.375 3.375 0 0 0-3.375-3.375h-1.5A1.125 1.125 0 0 1 13.5 7.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H8.25m.75 12 3 3m0 0 3-3m-3 3v-6m-1.5-9H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 0 0-9-9Z"
            />
          </svg>
          {{ $t("update.profile_picture.import") }}
        </template>
      </button>
    </div>
  </UpdateModal>
</template>

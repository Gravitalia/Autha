<script setup>
import { useUser } from "../stores/user";

const user = useUser();
user.fetchUser();

const isMenuOpened = ref(false);
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
});
</script>

<template>
  <div
    absolute
    z-50
    font-sans
    font-medium
    w-full
    flex
    items-center
    p-2
    text-zinc-700
    rounded
    dark:text-white
    group
    border-none
    cursor-pointer
    @click="isMenuOpened = !isMenuOpened"
  >
    <NuxtImg
      v-if="user.avatar && user.avatar.length !== 0"
      w-6
      h-6
      rounded-full
      :src="
        useRuntimeConfig().public.CDN_URL + '/t_avatar/' + user.avatar + '.webp'
      "
    />
    <canvas
      v-else
      ref="canvas"
      width="150px"
      height="150px"
      rounded-full
      w-6
      h-6
    ></canvas>
    <div v-if="user.username.length === 0" animate-pulse>
      <div h-2.5 bg-zinc-300 rounded-full dark:bg-zinc-700 w-26 ml-3></div>
      <span sr-only>{{ $t("screen_reader.loading") }}</span>
    </div>
    <span v-else ml-3 text-base>{{ user.username }}</span>
  </div>

  <div v-if="isMenuOpened" absolute pt-12 ml-6 xl:pt-0 xl:ml-66>
    <!--
      <svg
        class="absolute bottom-17"
        width="22"
        height="13"
        viewBox="0 0 30 20"
        xmlns="http://www.w3.org/2000/svg"
      >
        <polygon
          fill-white
          stroke-zinc-300
          dark:fill-dark
          dark:stroke-dark
          points="15, 0 30, 20 0, 20"
        />
      </svg>
    -->
    <div
      w-46
      xl:w-64
      rounded
      shadow-lg
      py-1
      bg-zinc-50
      dark:bg-dark
      border-zinc-300
      dark:border
      dark:border-zinc-700
      ring-1
      ring-black
      ring-opacity-5
      focus:outline-none
      role="menu"
      aria-orientation="horizontal"
    >
      <div flex px-5 p-2 grid gap-10 xl:gap-6 grid-cols-2 xl:grid-cols-3>
        <NuxtLink
          to="/"
          flex
          flex-col
          items-center
          justify-center
          no-underline
          space-y-0
        >
          <NuxtImg
            v-if="user.avatar"
            hover:bg-zinc-100
            rounded-full
            p-1.5
            w-9
            h-9
            :src="
              useRuntimeConfig().public.CDN_URL +
              '/t_avatar/' +
              user.avatar +
              '.webp'
            "
          />
          <NuxtImg
            v-else
            hover:bg-zinc-100
            rounded-full
            p-1.5
            w-9
            h-9
            :src="canvas.toDataURL()"
          ></NuxtImg>
          <p text-sm text-zinc-700>{{ $t("account") }}</p>
        </NuxtLink>

        <NuxtLink
          to="https://www.gravitalia.com/"
          flex
          flex-col
          items-center
          justify-center
          no-underline
          space-y-0
        >
          <NuxtImg
            hover:bg-zinc-100
            hover:rounded-full
            p-1.5
            src="/favicon.webp"
            w-9
            h-9
          />
          <p text-sm text-zinc-700>Gravitalia</p>
        </NuxtLink>
      </div>
      <hr h-px bg-zinc-300 border-0 dark:bg-zinc-700 />
      <div px-4 py-2 flex flex-col justify-center>
        <div flex justify-center space-x-4>
          <NuxtLink
            text-xs
            text-zinc-700
            hover:text-zinc-900
            no-underline
            to="/terms"
            >{{ $t("terms_of_service") }}</NuxtLink
          >
          <NuxtLink text-xs> • </NuxtLink>
          <NuxtLink
            text-xs
            text-zinc-700
            hover:text-zinc-900
            no-underline
            to="/privacy"
            >{{ $t("p_policy") }}</NuxtLink
          >
        </div>
      </div>
    </div>
  </div>
</template>

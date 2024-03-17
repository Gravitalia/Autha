<script setup>
import { useUser } from "../../stores/user";

const query = useRoute().query;
const user = useUser();
user.fetchUser();

// Redirect if user is not connected to the login page.
if (useCookie("session").value === "" || user.vanity === "")
  await navigateTo("/signin");

const bot = {
  avatar: "4b8d0dc4ed86b54c8472d3fd17aef855",
  username: "Suba",
};

function authorize() {
  fetch(
    `${
      useRuntimeConfig().public?.API_URL ?? "https://oauth.gravitalia.com"
    }/oauth2/authorize?client_id=${query?.client_id}&redirect_uri=${query?.redirect_uri}&response_type=code&scope=${query?.scope}${query?.state ? `&state=${query.state}` : ""}`,
    {
      redirect: "follow",
      method: "POST",
      headers: { Authorization: useCookie("token").value },
    },
  );
}
</script>

<template>
  <!-- Blurry effect in background. -->
  <FontBubbles />

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
      2xl:w-26rem
      2xl:h-26rem
      shadow-lg
    >
      <div mt-6 lg:mt-10 mb-8 lg:mb-10 divide-x space-x-2 container>
        <NuxtImg
          rounded
          width="50"
          height="50"
          draggable="false"
          alt=""
          :src="
            bot?.avatar
              ? useRuntimeConfig().public.CDN_URL +
                '/t_avatar/' +
                bot.avatar +
                '.webp'
              : `https://www.gravitalia.com/avatar/${bot?.username ? (bot?.username[0].match(/[A-z]/) ? bot?.username[0]?.toUpperCase() : 'A') : 'A'}.webp`
          "
        />
      </div>
      <div flex-col container>
        <p text-lg font-semibold>
          {{ bot?.username }} {{ $t("wants_access_account") }}
        </p>
        <div flex items-center>
          <div
            w-6
            h-6
            rounded-full
            bg-green-300
            flex
            justify-center
            items-center
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              fill="none"
              viewBox="0 0 24 24"
              stroke-width="1.5"
              stroke="currentColor"
              w-4
              h-4
              text-gray-700
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M4.5 12.75l6 6 9-13.5"
              />
            </svg>
          </div>
          <p ml-2>
            {{ $t("scopes.identity") }}
          </p>
        </div>
      </div>

      <div flex container>
        <div flex justify-between w-16.5rem lg:w-18.5rem mt-11>
          <NuxtLink
            :to="`${query.redirect_uri.includes('http') ? query.redirect_uri : 'https://' + query.redirect_uri}?error=access_denied&error_description=The+resource+owner+or+authorization+server+denied+the+request${query.state ? '&state=' + query.state : ''}`"
            btn-invisible
            no-underline
          >
            {{ $t("cancel") }}
          </NuxtLink>

          <button btn-base @click="authorize">
            {{ $t("authorize") }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

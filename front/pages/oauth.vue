<script setup lang="ts">
import { useUser } from "../stores/user";

const user = useUser();
user.fetchUser();

// Redirect if user is not connected to the login page.
if (useCookie("session").value === "" || user.vanity === "")
  await navigateTo("/signin");
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
      <h1>{{ $t("oauth.title") }}</h1>
      <p text-zinc-700 mb-3>
        {{ $t("oauth.description") }}
      </p>

      <div w-full flex flex-col xl:flex-row justify-between>
        <Card :title="$t('oauth.applications.title')">
          <div p-2 flex flex-col items-center>
            <NuxtImg w-56 xl:w-72 src="/cluster.svg" draggable="false" />
            <p pt-1 font-semibold>{{ $t("oauth.applications.empty") }}</p>
          </div>
        </Card>

        <Card :title="$t('oauth.linked.title')">
          <div p-2 px-12 flex flex-col items-center>
            <!-- Gravitalia. -->
            <div w-full px-4 py-3 flex items-center justify-between>
              <NuxtImg width="35" w-9 src="/favicon.webp" draggable="false" />
              <p font-semibold>Gravitalia</p>
              <span
                px-2
                h-6
                flex
                items-center
                rounded-full
                bg-green-200
                text-green-900
                uppercase
                font-medium
                text-xs
                >{{ $t("linked") }}</span
              >
            </div>
            <hr h-px my-8 bg-gray-600 border-0 dark:bg-gray-700 />
          </div>
        </Card>
      </div>
    </div>
  </div>
</template>

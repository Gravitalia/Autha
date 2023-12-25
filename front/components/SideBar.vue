<script setup lang="ts">
import { ref } from "vue";
import { useUser } from "../stores/user";

const user = useUser();
user.fetchUser();

const isSideBarOpened: Ref<boolean> = ref(false);
const path = useRoute().path;

// Logout user using Pinia, then redercting user to the login page.
async function logout() {
  user.logout();
  await navigateTo("/signin");
}
</script>

<template>
  <!-- Open sidebar button. -->
  <button
    inline-flex
    border-none
    items-center
    p-2
    mt-2
    ml-3
    text-sm
    text-zinc-500
    rounded
    sm:hidden
    hover:bg-zinc-100
    focus:outline-none
    focus:ring-2
    focus:ring-zinc-200
    dark:text-zinc-400
    dark:hover:bg-zinc-700
    dark:focus:ring-zinc-600
    type="button"
    @click="isSideBarOpened = !isSideBarOpened"
  >
    <span sr-only>Open sidebar</span>
    <svg
      w-6
      h-6
      aria-hidden="true"
      fill="currentColor"
      viewBox="0 0 20 20"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        clip-rule="evenodd"
        fill-rule="evenodd"
        d="M2 4.75A.75.75 0 012.75 4h14.5a.75.75 0 010 1.5H2.75A.75.75 0 012 4.75zm0 10.5a.75.75 0 01.75-.75h7.5a.75.75 0 010 1.5h-7.5a.75.75 0 01-.75-.75zM2 10a.75.75 0 01.75-.75h14.5a.75.75 0 010 1.5H2.75A.75.75 0 012 10z"
      ></path>
    </svg>
  </button>

  <aside
    :class="isSideBarOpened ? 'transform-none' : '-translate-x-full'"
    aria-label="Sidebar"
    fixed
    top-0
    left-0
    z-40
    w-64
    h-screen
    transition-transform
    sm:translate-x-0
  >
    <div h-full px-3 py-4 overflow-y-auto bg-zinc-50 dark:bg-dark>
      <div space-y-2 font-medium>
        <!-- Logo -->
        <div class="flex mb-4">
          <NuxtImg
            alt="Gravitalia"
            src="/favicon.webp"
            width="40"
            draggable="false"
          />

          <h3 ml-12 mt-0.5rem absolute>Gravitalia</h3>

          <!-- Close sidebar button. -->
          <button
            block
            md:hidden
            border-none
            ml-auto
            mt-1
            type="button"
            @click="isSideBarOpened = false"
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 24 24"
              rounded
              flex-shrink-0
              w-6
              h-5
              fill-zinc-500
              transition
              duration-75
              dark:fill-zinc-400
              group-hover:fill-zinc-900
              dark:group-hover:fill-white
            >
              <path
                d="M12.0007 10.5865L16.9504 5.63672L18.3646 7.05093L13.4149 12.0007L18.3646 16.9504L16.9504 18.3646L12.0007 13.4149L7.05093 18.3646L5.63672 16.9504L10.5865 12.0007L5.63672 7.05093L7.05093 5.63672L12.0007 10.5865Z"
              ></path>
            </svg>
          </button>
        </div>

        <!-- Links -->
        <NuxtLink
          to="/"
          prefetch
          :class="
            path === '/'
              ? 'bg-zinc-100 dark:bg-zinc-700 group'
              : 'hover:bg-zinc-100 dark:hover:bg-zinc-700 group'
          "
          no-underline
          flex
          items-center
          p-2
          text-zinc-900
          rounded
          dark:text-white
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            flex-shrink-0
            w-6
            h-6
            fill-zinc-500
            transition
            duration-75
            dark:fill-zinc-400
            group-hover:fill-zinc-900
            dark:group-hover:fill-white
          >
            <path
              d="M16 2L21 7V21.0082C21 21.556 20.5551 22 20.0066 22H3.9934C3.44476 22 3 21.5447 3 21.0082V2.9918C3 2.44405 3.44495 2 3.9934 2H16ZM12 11.5C13.3807 11.5 14.5 10.3807 14.5 9C14.5 7.61929 13.3807 6.5 12 6.5C10.6193 6.5 9.5 7.61929 9.5 9C9.5 10.3807 10.6193 11.5 12 11.5ZM7.52746 17H16.4725C16.2238 14.75 14.3163 13 12 13C9.68372 13 7.77619 14.75 7.52746 17Z"
            ></path>
          </svg>

          <span ml-3>{{ $t("about") }}</span>
        </NuxtLink>

        <NuxtLink
          to="/security"
          :class="
            path === '/security'
              ? 'bg-zinc-100 dark:bg-zinc-700 group'
              : 'hover:bg-zinc-100 dark:hover:bg-zinc-700 group'
          "
          no-underline
          flex
          items-center
          p-2
          text-zinc-900
          rounded
          dark:text-white
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            flex-shrink-0
            w-6
            h-6
            fill-zinc-500
            transition
            duration-75
            dark:fill-zinc-400
            group-hover:fill-zinc-900
            dark:group-hover:fill-white
          >
            <path
              d="M18 8H20C20.5523 8 21 8.44772 21 9V21C21 21.5523 20.5523 22 20 22H4C3.44772 22 3 21.5523 3 21V9C3 8.44772 3.44772 8 4 8H6V7C6 3.68629 8.68629 1 12 1C15.3137 1 18 3.68629 18 7V8ZM11 15.7324V18H13V15.7324C13.5978 15.3866 14 14.7403 14 14C14 12.8954 13.1046 12 12 12C10.8954 12 10 12.8954 10 14C10 14.7403 10.4022 15.3866 11 15.7324ZM16 8V7C16 4.79086 14.2091 3 12 3C9.79086 3 8 4.79086 8 7V8H16Z"
            ></path>
          </svg>

          <span ml-3>{{ $t("security") }}</span>
        </NuxtLink>

        <NuxtLink
          to="/data"
          :class="
            path === '/data'
              ? 'bg-zinc-100 dark:bg-zinc-700 group'
              : 'hover:bg-zinc-100 dark:hover:bg-zinc-700 group'
          "
          no-underline
          flex
          items-center
          p-2
          text-zinc-900
          rounded
          dark:text-white
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            flex-shrink-0
            w-6
            h-6
            fill-zinc-500
            transition
            duration-75
            dark:fill-zinc-400
            group-hover:fill-zinc-900
            dark:group-hover:fill-white
          >
            <path
              d="M3 3H21C21.5523 3 22 3.44772 22 4V20C22 20.5523 21.5523 21 21 21H3C2.44772 21 2 20.5523 2 20V4C2 3.44772 2.44772 3 3 3ZM16.4645 15.5355L20 12L16.4645 8.46447L15.0503 9.87868L17.1716 12L15.0503 14.1213L16.4645 15.5355ZM6.82843 12L8.94975 9.87868L7.53553 8.46447L4 12L7.53553 15.5355L8.94975 14.1213L6.82843 12ZM11.2443 17L14.884 7H12.7557L9.11597 17H11.2443Z"
            ></path>
          </svg>

          <span ml-3>{{ $t("data") }}</span>
        </NuxtLink>

        <NuxtLink
          to="/oauth"
          :class="
            path === '/oauth'
              ? 'bg-zinc-100 dark:bg-zinc-700 group'
              : 'hover:bg-zinc-100 dark:hover:bg-zinc-700 group'
          "
          no-underline
          flex
          items-center
          p-2
          text-zinc-900
          rounded
          dark:text-white
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            flex-shrink-0
            w-6
            h-6
            fill-zinc-500
            transition
            duration-75
            dark:fill-zinc-400
            group-hover:fill-zinc-900
            dark:group-hover:fill-white
          >
            <path
              d="M12 1C16.9706 1 21 5.02944 21 10V14C21 17.0383 19.4945 19.7249 17.1887 21.3546C17.7164 19.6635 18 17.8649 18 16L17.9996 13.999H15.9996L16 16L15.997 16.3149C15.9535 18.5643 15.4459 20.7 14.5657 22.6304C13.7516 22.8705 12.8909 23 12 23C11.6587 23 11.3218 22.981 10.9903 22.944C12.2637 20.9354 13 18.5537 13 16V9H11V16L10.9963 16.2884C10.9371 18.5891 10.1714 20.7142 8.90785 22.4547C7.9456 22.1028 7.05988 21.5909 6.28319 20.9515C7.35876 19.5892 8 17.8695 8 16V10L8.0049 9.80036C8.03767 9.1335 8.23376 8.50957 8.554 7.96773L7.10935 6.52332C6.41083 7.50417 6 8.70411 6 10V16L5.99586 16.2249C5.95095 17.4436 5.54259 18.5694 4.87532 19.4973C3.69863 17.9762 3 16.0697 3 14V10C3 5.02944 7.02944 1 12 1ZM12 4C10.7042 4 9.50434 4.41077 8.52353 5.10921L9.96848 6.55356C10.5639 6.20183 11.2584 6 12 6C14.2091 6 16 7.79086 16 10V12H18V10C18 6.68629 15.3137 4 12 4Z"
            ></path>
          </svg>

          <span ml-3>{{ $t("oauth") }}</span>
        </NuxtLink>

        <button
          font-sans
          font-medium
          w-full
          flex
          items-center
          p-2
          text-zinc-900
          rounded
          dark:text-white
          bg-zinc-50
          hover:bg-zinc-100
          dark:hover:bg-zinc-700
          group
          border-none
          cursor-pointer
          type="button"
          @click="logout()"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            flex-shrink-0
            w-6
            h-6
            fill-zinc-500
            transition
            duration-75
            dark:fill-zinc-400
            group-hover:fill-zinc-900
            dark:group-hover:fill-white
          >
            <path
              d="M5 2H19C19.5523 2 20 2.44772 20 3V21C20 21.5523 19.5523 22 19 22H5C4.44772 22 4 21.5523 4 21V3C4 2.44772 4.44772 2 5 2ZM9 11V8L4 12L9 16V13H15V11H9Z"
            ></path>
          </svg>

          <span ml-3 text-base>{{ $t("logout") }}</span>
        </button>
      </div>
    </div>
  </aside>
</template>

import { isDevelopment } from "std-env";

export default defineNuxtConfig({
  app: {
    keepalive: true,
    head: {
      charset: "utf-8",
      viewport: "width=device-width,initial-scale=1",
      title: "Gravitalia",
      htmlAttrs: {
        lang: "en",
      },
      meta: [
        { property: "og:type", content: "website" },
        { property: "og:site_name", content: "Gravitalia" },
        { property: "og:title", content: "Gravitalia" },
        { property: "og:image", content: "/favicon.webp" },
        {
          name: "og:description",
          content: "Gravitalia, let us connect you to the Christmas spirit! 🎅",
        },
        { name: "theme-color", content: "#CA2555" },
        { name: "robots", content: "index, follow" },
        { name: "twitter:card", content: "summary" },
        { name: "twitter:site", content: "@gravitalianews" },
        {
          name: "description",
          content: "Gravitalia, let us connect you to the Christmas spirit! 🎅",
        },
      ],
      link: [{ rel: "manifest", href: "/manifest.json" }],
      script: [
        {
          innerHTML: !isDevelopment
            ? '"serviceWorker"in navigator&&navigator.serviceWorker.register("/sw.js",{scope:"/"})'
            : "",
        },
      ],
      bodyAttrs: {
        class: "dark:bg-zinc-900 dark:text-white font-sans",
      },
    },
  },

  ssr: true,
  components: true,
  sourcemap: isDevelopment,

  modules: [
    "@pinia/nuxt",
    "@unocss/nuxt",
    [
      "@nuxtjs/color-mode",
      {
        preference: "system",
        fallback: "light",
        hid: "color-script",
        globalName: "__NUXT_COLOR_MODE__",
        componentName: "ColorScheme",
        classPrefix: "",
        classSuffix: "",
        storageKey: "mode",
      },
    ],
    [
      "@nuxtjs/i18n",
      {
        defaultLocale: "en",
        strategy: "no_prefix",
        lazy: false,
        langDir: "locales",
        detectBrowserLanguage: {
          useCookie: true,
          cookieKey: "locale",
          redirectOn: "root",
          fallbackLocale: "en",
          alwaysRedirect: true,
        },
        locales: [
          {
            code: "en",
            iso: "en-US",
            file: "en-US.json",
            name: "English",
          },
          {
            code: "fr",
            iso: "fr-FR",
            file: "fr-FR.json",
            name: "Français",
          },
        ],
        baseUrl: "https://www.gravitalia.com",
      },
    ],
    "~/modules/purge-comments",
  ],

  devtools: { enabled: true },
  runtimeConfig: {
    public: {
      CDN_URL:
        "https://res.cloudinary.com/dimtq5hwr/image/upload/s--4SMIfypA--",
    },
  },

  pinia: {
    storesDirs: ["./stores/**"],
  },

  nitro: {
    // preset: "cloudflare_pages",
  },

  experimental: {
    headNext: true,
    payloadExtraction: false,
    inlineSSRStyles: false,
    renderJsonPayloads: true,
  },

  vue: {
    defineModel: true,
    propsDestructure: true,
  },
});
import { isDevelopment } from 'std-env';

export default defineNuxtConfig({
  app: {
    keepalive: true,
    head: {
      charset: "utf-8",
      viewport: "width=device-width,initial-scale=1",
      title: "Gravitalia",
      htmlAttrs: {
        lang: "en"
      },
      meta: [
        { property: "og:type", content: "website" },
        { property: "og:site_name", content: "Gravitalia" },
        { property: "og:title", content: "Gravitalia" },
        { property: "og:image", content: "/favicon.webp" },
        { name: "og:description", content: "Gravitalia, let us connect you to the Christmas spirit! 🎅" },
        { name: "theme-color", content: "#CA2555" },
        { name: "robots", content: "index, follow" },
        { name: "twitter:card", content: "summary" },
        { name: "twitter:site", content: "@gravitalianews" },
        { name: "description", content: "Gravitalia, let us connect you to the Christmas spirit! 🎅" },
      ],
      link: [
        { rel: "icon", type: "image/webp", href: "/favicon.webp" },
        { rel: 'apple-touch-icon', href: "/favicon.webp" },
        { rel: "manifest", href: "/manifest.json" },
      ],
      script: [
        { innerHTML: !isDevelopment ? '"serviceWorker"in navigator&&navigator.serviceWorker.register("/sw.js",{scope:"/"});' : "" },
      ],
      bodyAttrs: {
        class: "dark:bg-zinc-900 dark:text-white font-sans",
      }
    }
  },

  ssr: true,
  components: true,
  sourcemap: isDevelopment,
  
  modules: [
    "@unocss/nuxt",
    ["@nuxtjs/color-mode", {
      preference: "system",
      fallback: "light",
      hid: "color-script",
      globalName: "__NUXT_COLOR_MODE__",
      componentName: "ColorScheme",
      classPrefix: "",
      classSuffix: "",
      storageKey: "mode"
    }],
    "~/modules/purge-comments",
  ],

  devtools: { enabled: true },

  nitro: {
    //preset: "cloudflare_pages",
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
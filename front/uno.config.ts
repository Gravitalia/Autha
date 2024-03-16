import {
  defineConfig,
  presetAttributify,
  presetTypography,
  presetUno,
  presetMini,
} from "unocss";

export default defineConfig({
  presets: [
    presetAttributify(),
    presetUno(),
    presetTypography(),
    presetMini({
      dark: "class",
    }),
  ],
  shortcuts: {
    "blur-5xl": "blur-260px",
    "bg-primary": "bg-violet-600 dark:bg-violet-500",
    "bg-secondary": "bg-amber-400 dark:bg-amber-600",

    "btn-base":
      "text-sm px-4 py-2 cursor-pointer outline-none border-none rounded bg-primary enabled:hover:shadow enabled:hover:bg-violet-800 enabled:dark:hover:bg-violet-600 font-medium text-white disabled:opacity-75 transition-all duration-200 disabled:cursor-not-allowed",
    "btn-invisible":
      "text-sm px-2 py-2 cursor-pointer bg-none border-none outline-none rounded text-violet-500 dark:text-white font-medium hover:bg-violet-50 dark:hover:bg-violet-500 transition-colors duration-200",

    input:
      "w-64 lg:w-72 h-7 text-sm text-zinc-700 dark:text-zinc-200 dark:placeholder:text-zinc-300 outline-none bg-transparent border border-zinc-400 dark:border-zinc-700 border-b-2 border-x-0 border-t-0",
    "text-link":
      "text-violet-600 dark:text-violet-500 hover:text-violet-700 dark:hover:text-violet-600 no-underline hover:underline",

    container: "flex justify-center items-center",
  },
});

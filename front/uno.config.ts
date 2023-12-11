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
    "blur-5xl": "blur-300px",
    "bg-primary": "bg-violet-700 dark:bg-violet-500",
    "bg-secondary": "bg-amber-400 dark:bg-amber-600",

    "btn-base":
      "text-sm px-4 py-2 cursor-pointer outline-none border-none rounded bg-primary hover:bg-violet-800 dark:hover:bg-violet-600 font-medium text-white disabled:opacity-75 transition-colors duration-200 disabled:cursor-not-allowed",

    "container": "flex justify-center items-center"
  },
});

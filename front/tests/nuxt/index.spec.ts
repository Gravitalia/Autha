import { describe, test, expect } from "vitest";
import { setup, $fetch } from "@nuxt/test-utils";

await setup({
  server: true,
});

describe("index page", () => {
  test("contains doctype", async () => {
    const html = await $fetch("/");
    expect(html.slice(0, 15)).toMatchInlineSnapshot(`"<!DOCTYPE html>"`);
  });
});

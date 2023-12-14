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
</template>

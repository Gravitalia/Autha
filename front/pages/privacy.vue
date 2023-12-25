<script setup>
useHead({
  htmlAttrs: {
    lang: useI18n().locale,
  },
  link: [{ rel: "canonical", href: "https://account.gravitalia.com/privacy" }],
  title: useI18n().t("privacy.title"),
});
</script>

<template>
  <div flex flex-col justify-center items-center>
    <div class="w-5/6 md:w-2/3">
      <h1 py-2 text-4xl font-bold text-center>{{ $t("privacy.title") }}</h1>

      <p>
        <b>{{ $t("date") }}</b> 01/04/2023
      </p>

      <div py-2 space-y-4>
        <p>
          {{ $t("privacy.description[0]") }}
        </p>

        <p>
          {{ $t("privacy.description[1]") }}
        </p>

        <p text-sm italic>
          {{ $t("privacy.description[2]") }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>
        {{ $t("privacy.data_we_collect.title") }}
      </h2>
      <h3 pt-3 font-bold ml-8 text-lg>
        {{ $t("privacy.data_we_collect.provided.title") }}
      </h3>

      <div pt-3 ml-8>
        <p>
          - <b>{{ $t("privacy.data_we_collect.provided.account.title") }}</b>
          {{ $t("privacy.data_we_collect.provided.account.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.data_we_collect.provided.content.title") }}</b>
          {{ $t("privacy.data_we_collect.provided.content.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.data_we_collect.provided.payments.title") }}</b>
          {{ $t("privacy.data_we_collect.provided.payments.description") }}
        </p>
        <p>
          -
          <b>{{ $t("privacy.data_we_collect.provided.interactions.title") }}</b>
          {{ $t("privacy.data_we_collect.provided.interactions.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.data_we_collect.provided.other.title") }}</b>
          {{ $t("privacy.data_we_collect.provided.other.description") }}
        </p>
      </div>

      <h3 pt-3 font-bold ml-8 text-lg>
        {{ $t("privacy.data_we_collect.what.title") }}
      </h3>

      <div pt-3 ml-8>
        <p>
          - <b>{{ $t("privacy.data_we_collect.what.device.title") }}</b>
          {{ $t("privacy.data_we_collect.what.device.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.data_we_collect.what.cookies.title") }}</b>
          {{ $t("privacy.data_we_collect.what.cookies.description") }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>
        {{ $t("privacy.how.title") }}
      </h2>

      <div pt-3 ml-8>
        <p>
          - <b>{{ $t("privacy.how.services.title") }}</b>
          {{ $t("privacy.how.services.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.how.security.title") }}</b>
          {{ $t("privacy.how.security.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.how.contact.title") }}</b>
          {{ $t("privacy.how.contact.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.how.service.title") }}</b>
          {{ $t("privacy.how.service.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.how.improve_service.title") }}</b>
          {{ $t("privacy.how.improve_service.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.how.vital.title") }}</b>
          {{ $t("privacy.how.vital.description") }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>
        {{ $t("privacy.share.title") }}
      </h2>

      <div pt-3 ml-8>
        <p>
          - <b>{{ $t("privacy.share.consent.title") }}</b>
          {{ $t("privacy.share.consent.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.share.when.title") }}</b>
          {{ $t("privacy.share.when.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.share.contact.title") }}</b>
          {{ $t("privacy.share.contact.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.share.suppliers.title") }}</b>
          {{ $t("privacy.share.suppliers.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.share.legal.title") }}</b>
          {{ $t("privacy.share.legal.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.share.emergency.title") }}</b>
          {{ $t("privacy.share.emergency.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.share.merger.title") }}</b>
          {{ $t("privacy.share.merger.description") }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>
        {{ $t("privacy.international.title") }}
      </h2>
      <p pt-3>
        {{ $t("privacy.international.description") }}
      </p>

      <h2 underline text-3xl font-bold>
        {{ $t("privacy.time.title") }}
      </h2>
      <div pt-3>
        <p>
          {{ $t("privacy.time.description[0]") }}
        </p>

        <p>
          {{ $t("privacy.time.description[1]") }}
        </p>

        <p>
          {{ $t("privacy.time.description[2]") }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>{{ $t("privacy.protection.title") }}</h2>
      <div pt-3 space-y-4>
        <p>
          {{ $t("privacy.protection.description[0]") }}
        </p>
        <p>
          {{ $t("privacy.protection.description[1]") }}
        </p>
        <p>
          {{ $t("privacy.protection.description[2]") }}
        </p>
        <p>
          {{ $t("privacy.protection.description[3]") }}
        </p>
        <p>
          {{ $t("privacy.protection.description[4]") }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>
        {{ $t("privacy.choice_data_managed.title") }}
      </h2>
      <div pt-3>
        <p>
          {{ $t("privacy.choice_data_managed.description[0]") }}
        </p>

        <p>
          {{ $t("privacy.choice_data_managed.description[1]") }}
        </p>
        <p>
          {{ $t("privacy.choice_data_managed.description[2]") }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>{{ $t("privacy.rights.title") }}</h2>
      <p pt-3>
        {{ $t("privacy.rights.description") }}
      </p>
      <div pt-3>
        <p>
          - <b>{{ $t("privacy.rights.access.title") }}</b>
          {{ $t("privacy.rights.access.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.rights.erasure.title") }}</b>
          {{ $t("privacy.rights.erasure.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.rights.rectification.title") }}</b>
          {{ $t("privacy.rights.rectification.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.rights.forgotten.title") }}</b>
          {{ $t("privacy.rights.forgotten.description") }}
        </p>
        <p>
          - <b>{{ $t("privacy.rights.withdrawal.title") }}</b>
          {{ $t("privacy.rights.withdrawal.description") }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>{{ $t("privacy.contact.title") }}</h2>
      <div pt-3 space-y-4>
        <p>
          {{ $t("privacy.contact.description[0]") }}
        </p>

        <p>
          {{ $t("privacy.contact.description[1]") }}
        </p>

        <p>{{ $t("privacy.contact.description[2]") }}</p>

        <p>
          -
          <b>{{ $t("privacy.contact.confidentiality") }}</b>
          privacy@gravitalia.com
        </p>
        <p>
          - <b>{{ $t("privacy.contact.dpo") }}</b> privacy@gravitalia.com
        </p>
        <p>
          - <b>{{ $t("privacy.contact.other") }}</b> contact@gravitalia.com
        </p>
      </div>
    </div>
  </div>
</template>

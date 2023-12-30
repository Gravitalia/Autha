<script setup>
useHead({
  htmlAttrs: {
    lang: useI18n().locale,
  },
  link: [{ rel: "canonical", href: "https://account.gravitalia.com/terms" }],
  title: useI18n().t("terms_of_use"),
});
</script>

<template>
  <div flex flex-col justify-center items-center>
    <div class="w-5/6 md:w-2/3">
      <h1 py-2 text-4xl font-bold text-center>{{ $t("terms_of_use") }}</h1>

      <p>
        <b>{{ $t("date") }}</b> 01/04/2023
      </p>

      <p py-2 space-y-4>
        {{ $t("terms.welcome") }}
        {{ $t("terms.description") }}
      </p>

      <h2 underline text-3xl font-bold>{{ $t("terms.definitions.title") }}</h2>
      <div mt-3>
        <p>
          {{ $t("terms.definitions.we") }}
        </p>
        <p>
          {{ $t("terms.definitions.user") }}
        </p>
        <p>
          {{ $t("terms.definitions.service") }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>{{ $t("terms.notice.title") }}</h2>
      <div mt-3>
        <p>
          {{ $t("terms.notice.host") }}
        </p>
        <p>
          {{ $t("terms.notice.content") }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>
        {{ $t("terms.service_usage.title") }}
      </h2>
      <div mt-3>
        <p>
          {{ $t("terms.service_usage.signed") }}
        </p>
        <br />
        <p>
          {{ $t("terms.service_usage.age") }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>
        {{ $t("terms.except.title") }}
      </h2>
      <p mt-3>
        {{ $t("terms.except.services") }}
      </p>

      <h2 underline text-3xl font-bold>{{ $t("terms.except_you.title") }}</h2>
      <div mt-3>
        <p>
          {{ $t("terms.except_you.description") }}
        </p>
        <p>{{ $t("terms.except_you.rules[0]") }}</p>
        <p>
          {{ $t("terms.except_you.rules[1]") }}
        </p>
        <p>
          {{ $t("terms.except_you.rules[2]") }}
        </p>
        <p>
          {{ $t("terms.except_you.rules[3]") }}
        </p>
        <p>
          {{ $t("terms.except_you.rules[4]") }}
        </p>
        <p>
          {{ $t("terms.except_you.rules[5]") }}
        </p>
        <p>
          {{ $t("terms.except_you.rules[6]") }}
        </p>
        <br />
        <p>
          {{ $t("terms.except_you.sentence") }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>
        {{ $t("terms.api.title") }}
      </h2>
      <h3 font-bold ml-8 text-lg>{{ $t("terms.api.introduction.title") }}</h3>
      <div mt-3>
        <p>
          {{ $t("terms.api.introduction.welcome") }}
        </p>
        <p>
          {{ $t("terms.api.introduction.security") }}
        </p>
      </div>

      <h3 font-bold ml-8 text-lg>{{ $t("terms.api.restrictions.title") }}</h3>
      <p mt-3>
        {{ $t("terms.api.restrictions.description") }}
      </p>

      <h3 font-bold ml-8 text-lg>{{ $t("terms.api.data.title") }}</h3>
      <div mt-3>
        <p>
          {{ $t("terms.api.data.privacy") }}
        </p>
        <p>
          {{ $t("terms.api.data.gdrp") }}
        </p>
      </div>

      <h3 font-bold ml-8 text-lg>{{ $t("terms.api.sanctions.title") }}</h3>
      <p mt-3>
        {{ $t("terms.api.sanctions.description") }}
      </p>

      <h2 underline text-3xl font-bold>{{ $t("terms.account.title") }}</h2>
      <div mt-3>
        <span v-html="$t('terms.account.services')"></span>
        <p>
          {{ $t("terms.account.contact") }}
        </p>
        <p>
          {{ $t("terms.account.responsible") }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>{{ $t("terms.your_content.title") }}</h2>
      <div mt-3>
        <p>
          {{ "terms.your_content.publish" }}
        </p>
        <span
          v-html="
            $t('terms.your_content.suspend') + ' ' + 'contact@gravitalia.com'
          "
        ></span>
      </div>

      <h2 underline text-3xl font-bold>{{ $t("terms.our_content.title") }}</h2>
      <p mt-3>
        {{ $t("terms.our_content.description") }}
      </p>

      <h2 underline text-3xl font-bold>
        {{ $t("terms.other_content.title") }}
      </h2>
      <p mt-3>
        {{ $t("terms.other_content.description") }}
      </p>

      <h2 underline text-3xl font-bold>{{ $t("terms.cancellation.title") }}</h2>
      <div mt-3>
        <p>
          <span underline font-bold>{{
            $t("terms.cancellation.will.title")
          }}</span>
          {{ $t("terms.cancellation.will.description") }}
        </p>
        <p>
          <span underline font-bold>{{
            $t("terms.cancellation.gravitalia.title")
          }}</span>
          {{ $t("terms.cancellation.gravitalia.description") }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>{{ $t("terms.services.title") }}</h2>
      <div clmt-3>
        <p>
          {{ $t("terms.services.description[0]") }}
        </p>
        <p>
          {{ $t("terms.services.description[1]") }}
        </p>
        <p>
          {{ $t("terms.services.description[2]") }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>
        {{ $t("terms.limitations.title") }}
      </h2>
      <div mt-3>
        <p text-sm>
          {{ $t("terms.limitations.description[0]") }}
        </p>
        <p>{{ $t("terms.limitations.description[1]") }}</p>
        <p>
          {{ $t("terms.limitations.description[2]") }}
        </p>
        <p>
          {{ $t("terms.limitations.description[3]") }}
        </p>
        <p>
          {{ $t("terms.limitations.description[4]") }}
        </p>
        <p>
          {{ $t("terms.limitations.description[5]") }}
        </p>
        <p>
          {{ $t("terms.limitations.description[6]") }}
        </p>
        <p>
          {{ $t("terms.limitations.description[7]") }}
        </p>
      </div>

      <h2 underline font-bold>
        <i>{{ $t("terms.note_bene.title") }}</i>
      </h2>
      <div mt-3>
        <p>
          {{ $t("terms.note_bene.anathema") }}
        </p>
        <p>
          {{ $t("terms.note_bene.suspend") }}
        </p>
      </div>
    </div>
  </div>
</template>

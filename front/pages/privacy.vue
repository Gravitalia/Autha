<script setup>
useHead({
  htmlAttrs: {
    lang: useI18n().locale,
  },
  link: [{ rel: "canonical", href: "https://account.gravitalia.com/privacy" }],
  title: useI18n().t("Privacy Policy"),
});
</script>

<template>
  <div flex flex-col justify-center items-center>
    <div class="w-5/6 md:w-2/3" text-dark dark:text-white>
      <h1 py-2 text-4xl font-bold text-center>{{ $t("Privacy Policy") }}</h1>

      <p>
        <b>{{ $t("Effective date:") }}</b> 01/04/2023
      </p>

      <div py-2 space-y-4>
        <p>
          {{
            $t(
              "Welcome to Gravitalia! Before creating an account, it may be interesting to read and know how your data is used and processed.",
            )
          }}
        </p>

        <p>
          {{
            $t(
              "With us, we strive to guarantee: security, reliability and above all respect for private life! We do not resell anything and we do not use any data collected for advertising purposes!",
            )
          }}
        </p>

        <p text-sm italic>
          {{
            $t(
              "The definitions described in the General Conditions of Use also apply here.",
            )
          }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>{{ $t("Data we collect") }}</h2>
      <h3 pt-3 font-bold ml-8 text-lg>
        {{ $t("a. What you provide us with") }}
      </h3>

      <div pt-3 ml-8>
        <p>
          - <b>{{ $t("The account") }}</b>
          {{
            $t(
              "when you create a Gravitalia account, you provide us with personal information (e-mail address, password, surname, first name); you may also, optionally, provide a telephone number or a date of birth.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("The content") }}</b>
          {{
            $t(
              "As soon as you upload a publication (photograph, video, file, messages, written material in draft or non-draft form), the information entered is recorded for redistribution on the platforms. Voice or video calls, on the other hand, are not recorded, although a cover image may be temporarily saved.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("Payments") }}</b>
          {{
            $t(
              "when you purchase (or offer) products or services, you may be asked to provide a valid payment method, as well as associated information, such as the holder's first and last name or billing address. In order to secure and facilitate the transaction, third-party services such as PayPal or Stripe will process this payment information. We may store certain payment information, such as invoices or the last four digits of the card number associated with the transaction.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("Your interactions") }}</b>
          {{
            $t(
              "we also collect data on your interactions. That is to say, platform publications (photography, written posts) liked, subscriptions (when you subscribe to a user), robots/applications you have created or authorized (to access your data), publications created, accounts blocked, groups you join or create, your connections to platforms, your purchases, as well as moderation decisions.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("Other information") }}</b>
          {{
            $t(
              "you may fill out a form or request verification of your account; when this happens, you may be asked to enter additional information about yourself or the organization you represent.",
            )
          }}
        </p>
      </div>

      <h3 pt-3 font-bold ml-8 text-lg>
        {{ $t("b. What we collect") }}
      </h3>

      <div pt-3 ml-8>
        <p>
          - <b>{{ $t("Your device") }}</b>
          {{
            $t(
              "we may also collect the IP address in order to ensure the security of Users and Services, for example by checking whether they are identical.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("Cookies") }}</b>
          {{
            $t(
              "we use cookies for security purposes, to store configuration information (chosen language, etc.) or connection information; in no case advertising cookies.",
            )
          }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>
        {{ $t("How we use this data") }}
      </h2>

      <div pt-3 ml-8>
        <p>
          - <b>{{ $t("To provide you with Services") }}</b>
          {{
            $t(
              "we use the data you provide to ensure that our Services work the way we want them to. For example, when you write a post, or share a photograph, we need to process it (to check that the content complies with our rules) and store it (to then redistribute it to other Users, and to the Internet). We may also use this data to enhance the functionality of certain Services.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("Guarantee security") }}</b>
          {{
            $t(
              "in order to guarantee the safety of all Users, we are constantly striving to improve security. Some data may be analyzed to prevent misuse or use contrary to our rules/terms and conditions. For instance, the analysis of certain texts or photographs may be carried out by automatic learning.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("To contact you") }}</b>
          {{
            $t(
              "we use the information provided to keep in touch with you and inform you of changes that affect you but also to set up a system of double authentication.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("To provide service Customer") }}</b>
          {{
            $t(
              "we use the information to answer your questions, investigate bugs, interact with you at convenient times, or otherwise.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("Improve our service") }}</b>
          {{
            $t(
              "we use this information to understand the interactions, to improve our visibility as well as the accessibility of our Services.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("Protect vital interests") }}</b>
          {{
            $t(
              "we can use, collect and share data if we believe that the physical or psychological integrity of a person is at stake (i.e. a car accident, resolving an emergency medical situation).",
            )
          }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>
        {{ $t("How we share your information") }}
      </h2>

      <div pt-3 ml-8>
        <p>
          - <b>{{ $t("With your consent") }}</b>
          {{
            $t(
              "when you authorize us to share your data with a third party or Users. Indeed, when you publish a photograph, or written content, we may, where your settings allow, disclose it to the web, i.e. publicly. In another case, when you purchase a good or service, the information may be transmitted to PayPal or Stripe to satisfy your request.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("When you share them") }}</b>
          {{
            $t(
              "by publishing content online, by providing public data (username, profile picture, etc.).",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("To contact you") }}</b>
          {{
            $t(
              "we use the information provided to keep in touch with you and inform you of changes that affect you but also to set up a system of double authentication.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("With our suppliers") }}</b>
          {{
            $t(
              "we delegate certain parts of our Services to trusted third parties, which enable the processing of information (e.g. payment) or the cloud providers that host our data.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("For legal issues") }}</b>
          {{
            $t(
              "when we believe it is in the interests of Gravitalia and the User, we may transmit data when required by law, for example during an investigation. Although we strive to limit abusive legal requests.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("In case of emergency") }}</b>
          {{
            $t(
              "if we believe that the physical or psychological integrity of someone is at stake, we can transmit certain data, in good faith to the departments concerned.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("Merger, buyout of Gravitalia") }}</b>
          {{
            $t(
              "in the event that Gravitalia is bought out, the data may be transmitted to its parent company.",
            )
          }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>
        {{ $t("International Data Transfers") }}
      </h2>
      <p pt-3>
        {{
          $t(
            "Data is only processed within Europe and more specifically within the European Union. We believe that data should remain in a secure and regulated location, which is why it is processed in Germany (Frankfurt), France (Paris) or Ireland (Dublin). For security reasons, data may be stored at several locations in the European Union (fault tolerance, edge computing), but will remain just as secure.",
          )
        }}
      </p>

      <h2 underline text-3xl font-bold>
        {{ $t("Data retention time") }}
      </h2>
      <div pt-3>
        <p>
          {{
            $t(
              "Data is kept for as long as is necessary for the purposes mentioned above. However, when we detect prolonged inactivity (approximately 5 years), an account deletion procedure may be initiated.",
            )
          }}
        </p>

        <p>
          {{
            $t(
              "When the account deletion procedure is initiated, access to your account is restricted: you can no longer log in, but your data remains intact. No more Users can access your account information, which appears as deleted.",
            )
          }}
        </p>

        <p>
          {{
            $t(
              'After 30 days (following the procedure), the data begins to be deleted (username, avatar, biography, etc.), with only the data that is important for security being kept and anonymised (the "vanity" to prevent identity theft, and the encrypted e-mail address).',
            )
          }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>{{ $t("Data protection") }}</h2>
      <div pt-3 space-y-4>
        <p>
          {{
            $t(
              "Safety is paramount with us! While no system is foolproof, we have strict standards for securing data.",
            )
          }}
        </p>
        <p>
          {{
            $t(
              "First, sensitive data is either encrypted (if it must be usable in the future: phone number, email adress, or date of birth, for example) or hashed (if it must be very secure, and non-recoverable : password, for example).",
            )
          }}
        </p>
        <p>
          {{
            $t(
              "Secondly, we put a minimum of security on the servers we use (firewalls, limited password attempts...) so that our critical infrastructures are not exposed too strongly.",
            )
          }}
        </p>
        <p>
          {{
            $t(
              "Also remember that all data transmitted between Gravitalia and you (and vice versa) is under the security padlock (HTTPS) which guarantees that the data is encrypted when in transit from your browser, through Cloudflare, and finally, to reach our servers.",
            )
          }}
        </p>
        <p>
          {{
            $t(
              "But security is played on several tables! If you haven't already done so, you can add double authentication and even opt for a unique and strong password!",
            )
          }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>
        {{ $t("Your choices about how your data is managed") }}
      </h2>
      <div pt-3>
        <p>
          {{
            $t(
              "We do not use your data for profit, nor resell it and even believe that the data must remain with the User.",
            )
          }}
        </p>

        <p>
          {{
            $t(
              "You are free to subscribe or unsubscribe from the various Services, communicate with whoever you want.",
            )
          }}
        </p>
        <p>
          {{
            $t(
              "You can choose, in the settings offered by each Service, whether or not to personalize your news feed. The personalization is done, not according to precise analyzes but simply from your “likes” (or button provided with this effigy).",
            )
          }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>{{ $t("Your rights") }}</h2>
      <p pt-3>
        {{
          $t(
            "Each Service offers in the “Settings” a part (generally called “Data”) allowing you to access your:",
          )
        }}
      </p>
      <div pt-3>
        <p>
          - <b>{{ $t("Access right") }}</b>
          {{
            $t(
              "which allows you to download the data collected about you. Please note that the information: banking, password and e-mail address are not provided when downloading the data.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("Right to erasure") }}</b>
          {{
            $t(
              'which gives you the possibility to delete your account globally or individually. When this right is applied, your account is deleted within 1 month (recoverable account), except for accounts linked to each Service which is deleted instantly, then the personal data (username, password, IP address... ) excluding email address and "vanity".',
            )
          }}
        </p>
        <p>
          - <b>{{ $t("Right of rectification") }}</b>
          {{
            $t(
              "you can modify at any time, via the “Settings” section, all the information collected about you.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("Right to be forgotten") }}</b>
          {{
            $t(
              "this right requires you to contact us by e-mail. Please include the right to be forgotten in the subject line of the e-mail and contact us via our e-mail address (provided below) with your identity card.",
            )
          }}
        </p>
        <p>
          - <b>{{ $t("Right of withdrawal") }}</b>
          {{
            $t(
              "when you register, you accept and approve having read the contracts, however, you can decide at any time to stop your commitment. To do this, simply follow the instructions of the right to erasure; you can no longer use our Services if you no longer wish to comply with our contracts.",
            )
          }}
        </p>
      </div>

      <h2 underline text-3xl font-bold>{{ $t("Contact us") }}</h2>
      <div pt-3 space-y-4>
        <p>
          {{
            $t(
              "You can contact us if you have any questions about this Privacy Policy. We look forward to hearing from you and helping you!",
            )
          }}
        </p>

        <p>
          {{ $t("You can also contact our DPO at the e-mail address below.") }}
        </p>

        <p>{{ $t("Enjoy using our Services!") }}</p>

        <p>
          -
          <b>{{ $t("Contact us about confidentiality:") }}</b>
          privacy@gravitalia.com
        </p>
        <p>
          - <b>{{ $t("Contact our DPO:") }}</b> privacy@gravitalia.com
        </p>
        <p>
          - <b>{{ $t("Other forms of contact:") }}</b> contact@gravitalia.com
        </p>
      </div>
    </div>
  </div>
</template>

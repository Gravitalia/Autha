<script setup>
useHead({
    htmlAttrs: {
        lang: useI18n().locale,
    },
    link: [
        { rel: "canonical", href: "https://account.gravitalia.com/terms" },
    ],
    title: useI18n().t("Terms of Service"),
});
</script>

<template>
    <div flex flex-col justify-center items-center>
        <div class="w-5/6 md:w-2/3">
            <h1 py-2 text-4xl font-bold text-center>{{ $t("Terms of Service") }}</h1>
    
            <p><b>{{ $t("Effective date:") }}</b> 01/04/2023</p>

            <p py-2 space-x-4>
                {{ $t("Welcome on Gravitalia! These terms and conditions govern the use of the services offered, including the programming interfaces (APIs) and the legal obligations of both parties.") }}
                {{ $t("Gravitalia offers places to share, to connect but also digital or physical tools to improve privacy.") }}
            </p>
    
            <h2 underline text-3xl font-bold>{{ $t("Definitions") }}</h2>
            <div mt-3>
                <p>{{ $t("The use of the terms \"we\", \"us\", \"our\" or \"Gravitalia\" refers to the Gravitalia entity, its subsidiaries and other companies.") }}</p>
                <p>{{ $t("The use of the terms \"User\", \"you\", \"your\" refers to you, as an individual or entity, while the use of the term \"Users\" refers to all registrants (including you, if applicable).") }}</p>
                <p>{{ $t("The use of the term \"Service\" (including \"Services\") refers both to Gravitalia's websites and products, and to the websites, products, and Services of its subsidiaries.") }}</p>
            </div>
    
            <h2 underline text-3xl font-bold>{{ $t("Legal notice") }}</h2>
            <div mt-3>
                <p>{{ $t("The host of Gravitalia is Contabo at Aschauer Str. 32a, 81549 Munich, Germany.") }}</p>
                <p>{{ $t("The content and site host is Cloudflare located at 101 Townsend St, San Francisco, CA 94107, USA.") }}</p>
            </div>
    
            <h2 underline text-3xl font-bold>{{ $t("Use of our Services") }}</h2>
            <div mt-3>
                <p>{{ $t("The Services offered are only available to Users who have approved and signed this contract binding you to Gravitalia; if you do not wish to accept this contract, it is imperative that you request the deletion of account (or that you do not create an account) via the Service provided for this purpose. In any case, the use of our Services must be done in compliance with the laws of your country: you must be 13 years old (or meet the digital majority in force in your country). In the event that you use the Services to represent a state, corporation or other legal entity, you represent that you have the rights and are in agreement with this Agreement.") }}</p>
                <br />
                <p>{{ $t("In the event that the User's age is below the numerical age of majority in his/her country (see above for details), the consent of his/her parents (as to the creation of the account and approval of this policy) or legal guardian is required.") }}</p>
            </div>
    
            <h2 underline text-3xl font-bold>{{ $t("What you can expect from us") }}</h2>
            <p mt-3>{{ $t("We set up multiple Services (websites, social networks, applications...) to satisfy you at best, while improving them, and try to develop new ones. Despite our efforts to avoid breakdowns (of Services, supplies...), we are likely, like any company, not to guarantee a Service without disruptions or even a total integrity of the data; we cannot be held responsible for these problems.") }}</p>
    
            <h2 underline text-3xl font-bold>{{ $t("What we expect from you") }}</h2>
            <div mt-3>
                <p>{{ $t("We want coexistence between our Users, without vituperation, with respect for others. To do this, you can follow the following principles:") }}</p>
                <p>{{ $t("- Comply with the laws in force in your country;") }}</p>
                <p>{{ $t("- Respect the intellectual property and integrity of authors and persons;") }}</p>
                <p>{{ $t("- Do not not attempt to interfere with the proper functioning of the Service;") }}</p>
                <p>{{ $t("- Not to defame, insult, defraud, harass or impersonate others;") }}</p>
                <p>{{ $t("- Not to post content likely to damage the image of those present;") }}</p>
                <p>{{ $t("- Do not post content disclosing sensitive information (health, etc.) about a person;") }}</p>
                <p>{{ $t("- Do not post racist, sexist, homophobic or xenophobic content;") }}</p>
                <br />
                <p>{{ $t("Gravitalia reserves the right to anathematize* any User who has not complied with the above rules.") }}</p>

            </div>
    
            <h2 underline text-3xl font-bold>{{ $t("Conditions of access to the API") }}</h2>
            <h3 font-bold ml-8 text-lg>{{ $t("a. Introduction") }}</h3>
            <div mt-3>
                <p>{{ $t("Of course, we welcome all developers who want to enrich the experience of our Users on our Services!") }}</p>
                <p>{{ $t("To perfect your ideas and to guarantee the security of our Users' data (even public), it is important to read these rules.") }}</p>
            </div>

            <h3 font-bold ml-8 text-lg>{{ $t("b. Restrictions") }}</h3>
            <p mt-3>{{ $t("You shall not attempt to: (a) perform analysis for the purpose of tracking and/or profiting from and commercially exploiting such data, (b) attempt to reverse engineer to derive private (non-<b>FOSS</b>) source code, know-how or trade secrets, (c) reproduce, redistribute, rent or sell access to the API, (d) access prohibited endpoints (oauth.gravitalia.com).") }}</p>

            <h3 font-bold ml-8 text-lg>{{ $t("c. Respect for data") }}</h3>
            <div mt-3>
                <p>{{ $t("In order to improve privacy, we expressly request the encryption of confidential data (email address, phone number...) when shared WITH EXPRESS USER AGREEMENT or even in cases where this data does not serve an explicit reading frame, the hashing of it.") }}</p>
                <p>{{ $t("In addition, we recommend that you comply with GDPR, CCPA/CCRA and LGPD. In the case of large applications or heavy usage, you will be required to provide a privacy policy, but also, and not limited to, proof of compliance, a comprehensive list of saved data, and proof of identity.") }}</p>
            </div>

            <h3 font-bold ml-8 text-lg>{{ $t("d. Sanctions") }}</h3>
            <p mt-3>{{ $t("In case of refusal to comply with these rules, sanctions may be applied against you such as the suspension of your application, your User account or even recourse to the competent courts.") }}</p>
    
            <h2 underline text-3xl font-bold>{{ $t("Your account") }}</h2>
            <div mt-3>
                <span v-html='$t("To enjoy the Services continuously, without interruption or blocking, you may need to have an account. The security of this account is your responsibility, you must provide a strong password (see <a class=\"text-blue-500 hover:text-blue-700\" href=\"https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online/use-a-strong-and-separate-password-for-email\">password</a>, NCSC: UK Government), check if your information has been compromised, etc. In case of loss, theft or damage related to your account, we cannot be held responsible.")'></span>
                <p>{{ $t("In addition, you may be asked for contact information (phone number, e-mail address), information aimed at authentication (password) or identification (username); for more information, visit the privacy page.") }}</p>
                <p>{{ $t("You are responsible for keeping your contact details up to date (e-mail address, for example), in the event of an impossibility to reach you, we will assume that all information has indeed been sent; we also assume that the communications made from your account or the contact details thereof have been made by you.") }}</p>
            </div>
    
            <h2 underline text-3xl font-bold>{{ $t("Your content") }}</h2>
            <div mt-3>
                <p>{{ "Some of our Services give you the possibility to publish content (in written, videographic, photographic or other form), as long as you send this content, you give us full rights to distribute, store, copy and communicate it. In addition, you represent and warrant to us that you have full rights to this work. This license is applicable worldwide, non-exclusive, free of charge and perpetual." }}</p>
                <span v-html='$t("<i>Ad nutum</i>, we reserve the right to temporarily or permanently delete or block your content, if it is contrary to our principles (cf. What we expect from you). When content is blocked, an email will normally be sent to the author, and the author may request a revised procedure by emailing <a class=\"text-blue-500 hover:text-blue-700\" href=\"mailto:contact@gravitalia.com\">contact@gravitalia.com</a>.")'></span>
            </div>

            <h2 underline text-3xl font-bold>{{ $t("Our content") }}</h2>
            <p mt-3>{{ $t("We may allow our content to be used on third party platforms but we retain all intellectual property rights. You are not permitted to obscure or alter any logos or trademarks.") }}</p>

            <h2 underline text-3xl font-bold>{{ $t("Other content") }}</h2>
            <p mt-3>{{ $t("We may make content available that we do not own through multiple Services. We cannot delegate the use of content. The content is not altered and may not reflect the opinion of Gravitalia.") }}</p>

            <h2 underline text-3xl font-bold>{{ $t("Cancellation") }}</h2>
            <div mt-3>
                <p><span underline font-bold>{{ $t("By your will:") }}</span> {{ $t("you are free to stop using the Services provided at any time without reason. You may delete your account, which will anonymize the data in your account (see Privacy Policy) or deactivate your account, if you are offered the option, which will suspend all processing of your personal information; such deactivation does not result in termination of this Agreement.") }}</p>
                <p><span underline font-bold>{{ $t("By Gravitalia:") }}</span> {{ $t("we reserve the right to suspend* your account or access (to a Service, site, software...) with or without notice if we believe that your account, or content is in violation of our principles.") }}</p>
            </div>

            <h2 underline text-3xl font-bold>{{ $t("Services provided") }}</h2>
            <div clmt-3>
                <p>{{ $t("The Services are provided “as is”. If you reside outside of the EEA or the UK, you agree that access to the Services is at your own risk.") }}</p>
                <p>{{ $t("WE (COMPANY, AFFILIATES) DISCLAIM, TO THE FULLEST EXTENT PERMITTED BY LAW, ANY EXPRESS OR IMPLIED WARRANTY OF MERCHANTABILITY. THE SERVICES ARE PROVIDED “AS IS”.") }}</p>
                <p>{{ $t("We disclaim all responsibility and liability for the availability, security and reliability of the Services.") }}</p>
            </div>

            <h2 underline text-3xl font-bold>{{ $t("Limitations and responsibilities") }}</h2>
            <div mt-3>
                <p text-sm>{{ $t("This section may not apply in certain countries or regions such as the EEA.") }}</p>
                <p>{{ $t("This contract is subject to French law.") }}</p>
                <p>{{ $t("Translations are given for information purposes only, in the event of a dispute, only the French version of the contracts (General Conditions of Use and Privacy Policy for example) may be used and only the French courts may be seized to settle this dispute.") }}</p>
                <p>{{ $t("Gravitalia cannot be held responsible for the information present on its site; the information disseminated is purely informative and is not intended to have true values.") }}</p>
                <p>{{ $t("Gravitalia cannot be held responsible for files downloaded by the User. This includes viruses or other computer/server infecting software.") }}</p>
                <p>{{ $t("Gravitalia cannot guarantee the integrity of the data and will not be liable for any incidental, special, exemplary or consequential damages, loss of profits, revenue, savings, business opportunities or customers, directly or indirectly.") }}</p>
                <p>{{ $t("WE CANNOT BE HELD RESPONSIBLE FOR THE CONTENT AND CONDUCT OF USERS OF OUR SERVICES AND THIS OF WAY ONLINE OR OFFLINE.") }}</p>
                <p>{{ $t("IN THE EVENT OF A DISPUTE, AN AMICABLE AGREEMENT SHOULD BE UNDERTAKEN PRIOR TO ANY COMPLAINT.") }}</p>
            </div>

            <h2 underline font-bold>Nota bene</h2>
            <div mt-3>
                <p>{{ $t("* The anathema employed will be, for example, an indexing on a private account suspension registry.") }}</p>
                <p>{{ $t("* The suspension will directly lead to the data anonymization process.") }}</p>
            </div>
        </div>
    </div>
</template>
import $ from "jquery";
import { arrayBufferToString, getChallenge, stringToArrayBuffer } from "./util";

(async () => {
  // Availability of `window.PublicKeyCredential` means WebAuthn is usable.
  if (
    window.PublicKeyCredential &&
    PublicKeyCredential.isConditionalMediationAvailable
  ) {
    // Check if conditional mediation is available.
    const isCMA = await PublicKeyCredential.isConditionalMediationAvailable();
    if (isCMA) {
      // To abort a WebAuthn call, instantiate an `AbortController`.
      const abortController = new AbortController();

      const challenge = await getChallenge();
      const publicKeyCredentialRequestOptions = {
        challenge: stringToArrayBuffer(challenge as string),
        rpId: location.hostname,
        userVerification: "required",

        // TBD: Allow user to select which credential to use.
        // allowCredentials: [],
      };

      const credential = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions,
        signal: abortController.signal,
        // Specify 'conditional' to activate conditional UI
        mediation: "conditional",
      });

      $.ajax({
        url: window.CMSScriptURI,
        method: "POST",
        data: {
          __mode: "login_passkey",
          challenge,
          id: credential?.id,
          clientDataJSON: btoa(
            arrayBufferToString((credential as any)?.response.clientDataJSON)
          ),
          authenticatorData: btoa(
            arrayBufferToString((credential as any)?.response.authenticatorData)
          ),
          signature: btoa(
            arrayBufferToString((credential as any)?.response.signature)
          ),
          type: credential?.type,

          // TBD: Add support for userHandle.
          // userHandle: arrayBufferToBase64(
          //   (credential as any)?.response.userHandle
          // ),
        },
        dataType: "json",
      }).then(({ error, result }) => {
        if (error) {
          alert(error);
          return;
        }

        location.href = result?.redirect_to;
      });
    }
  }
})();

// const form = document.querySelector("form") as HTMLFormElement;

// let rendered = false;

// function renderPasskeyForm() {
//   const data = {};
//   form.querySelectorAll("input").forEach((input) => {
//     data[input.name] = input.value;
//   });
//   data["__mode"] = "mfa_login_form";
//   $.ajax({
//     type: "POST",
//     url: form.action,
//     data,
//     dataType: "json",
//   }).then(
//     ({
//       error,
//       result,
//     }: {
//       error?: string;
//       result?: { html?: string; scripts?: string[] };
//     }) => {
//       if (error) {
//         document.querySelectorAll(".alert").forEach((el) => el.remove());
//         form.reset();

//         const alert = document.createElement("template");
//         alert.innerHTML =
//           '<div class="row"><div class="col-12"><div class="alert alert-danger" role="alert"></div></div></div>';
//         (alert.content.querySelector(".alert") as HTMLDivElement).textContent =
//           error;

//         const placeholder = document.querySelector("#msg-block");
//         placeholder?.parentElement?.insertBefore(
//           alert.content,
//           placeholder.nextSibling
//         );

//         return;
//       }

//       const { html, scripts } = result || {};

//       if (!html && (!scripts || scripts.length === 0)) {
//         // has not configured Passkey.
//         form.submit();
//         return;
//       }

//       rendered = true;

//       const fieldSelector =
//         "#username-field, #password-field, #remember-me, #remember-me + div";
//       document
//         .querySelectorAll(fieldSelector)
//         .forEach((el) => el.classList.add("d-none"));

//       const wrap = document.createElement("div");
//       wrap.innerHTML = html || "";
//       wrap.querySelector("#mfa-cancel")?.addEventListener("click", () => {
//         wrap.remove();
//         rendered = false;
//         document
//           .querySelectorAll(fieldSelector)
//           .forEach((el) => el.classList.remove("d-none"));
//       });
//       const placeholder = document.querySelector("#password-field");
//       placeholder?.parentElement?.insertBefore(wrap, placeholder.nextSibling);
//       const firstInputElement = wrap.querySelector("input");
//       if (firstInputElement) {
//         firstInputElement.focus();
//       }

//       (scripts || []).forEach((src) => {
//         if (document.querySelector(`script[src="${src}"]`)) {
//           return;
//         }

//         const script = document.createElement("script");
//         script.type = "module";
//         script.src = src;
//         document.body.appendChild(script);
//       });
//     }
//   );
// }

// form.addEventListener("submit", (ev) => {
//   if (rendered) {
//     return;
//   }

//   ev.preventDefault();
//   renderPasskeyForm();
// });

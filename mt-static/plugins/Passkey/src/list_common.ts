import $ from "jquery";
import {
  arrayBufferToString,
  getChallenge,
  stringToArrayBuffer,
  decodeBase64,
} from "./util";

const contentActions = document.querySelector<HTMLElement>("#content-actions")!;
contentActions.classList.add("d-none");

// Availability of `window.PublicKeyCredential` means WebAuthn is usable.
// `isUserVerifyingPlatformAuthenticatorAvailable` means the feature detection is usable.
// `​​isConditionalMediationAvailable` means the feature detection is usable.
if (
  window.PublicKeyCredential &&
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
  PublicKeyCredential.isConditionalMediationAvailable
) {
  // Check if user verifying platform authenticator is available.
  Promise.all([
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
    PublicKeyCredential.isConditionalMediationAvailable(),
  ]).then((results) => {
    if (results.every((r) => r === true)) {
      contentActions.classList.remove("d-none");
    }
  });
}

contentActions.addEventListener("click", async (ev) => {
  ev.preventDefault();
  const { userId, userName, userDisplayName, excludeIds, labelPrompt } =
    document.querySelector<HTMLElement>("[data-passkey-script]")?.dataset || {};

  const challenge = await getChallenge();
  const publicKeyCredentialCreationOptions = {
    challenge: stringToArrayBuffer(challenge as string),
    rp: {
      name: "Movable Type",
      id: location.hostname,
    },
    user: {
      id: stringToArrayBuffer(userId as string),
      name: userName,
      displayName: userDisplayName,
    },
    pubKeyCredParams: [
      { alg: -7, type: "public-key" },
      { alg: -257, type: "public-key" },
    ],
    excludeCredentials: JSON.parse(excludeIds as string).map((id: string) => ({
      id: stringToArrayBuffer(decodeBase64(id)),
      type: "public-key",
      transports: ["internal"],
    })),
    authenticatorSelection: {
      // authenticatorAttachment: "platform",
      requireResidentKey: true,
      userVerification: "required",
    },
  };

  const credential = await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions as any,
  }).catch((err) => {
    console.error(err);
    alert(err.message);
  });

  if (!credential) {
    return;
  }

  const label = window.prompt(labelPrompt);
  if (!label) {
    return;
  }

  $.ajax({
    url: window.CMSScriptURI,
    method: "POST",
    data: {
      __mode: "save_passkey",
      label,
      challenge,
      clientDataJSON: btoa(
        arrayBufferToString((credential as any)?.response.clientDataJSON)
      ),
      attestationObject: btoa(
        arrayBufferToString((credential as any)?.response.attestationObject)
      ),
      type: credential?.type,
    },
    dataType: "json",
  }).then((result) => {
    if (result.error) {
      alert(result.error);
      return;
    }

    location.href =
      window.CMSScriptURI +
      "?__mode=list&blog_id=0&_type=passkey&passkey_added=1";
  });
});

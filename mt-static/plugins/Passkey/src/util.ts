import $ from "jquery";
export function arrayBufferToString(buf: ArrayBuffer) {
  return String.fromCharCode(...new Uint8Array(buf));
}

export function stringToArrayBuffer(str: string): ArrayBuffer {
  return new Uint8Array([].map.call(str, (c: string) => c.charCodeAt(0)) as any)
    .buffer;
}

export function decodeBase64(str: string): string {
  return atob(str.replace(/-/g, "+").replace(/_/g, "/"));
}

export async function getChallenge() {
  return $.ajax({
    url: window.CMSScriptURI,
    method: "POST",
    data: {
      __mode: "challenge_passkey",
    },
    dataType: "json",
  }).then((result) => result.result.challenge);
}

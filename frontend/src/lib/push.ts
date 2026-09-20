import { endpoints } from "../api";

function urlBase64ToUint8Array(base64String: string): Uint8Array {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

function sameKey(a: ArrayBuffer | null | undefined, b: Uint8Array): boolean {
  if (!a) return false;
  const x = new Uint8Array(a);
  return x.length === b.length && x.every((v, i) => v === b[i]);
}

export function pushSupported(): boolean {
  return "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
}

export async function getPushStatus(): Promise<"subscribed" | "unsubscribed" | "unsupported" | "denied"> {
  if (!pushSupported()) return "unsupported";
  if (Notification.permission === "denied") return "denied";
  try {
    const reg = await navigator.serviceWorker.getRegistration();
    if (!reg) return "unsubscribed";
    const sub = await reg.pushManager.getSubscription();
    return sub ? "subscribed" : "unsubscribed";
  } catch {
    return "unsubscribed";
  }
}

/**
 * Confirm /sw.js is really JavaScript. When the file is missing, the dev
 * server / proxy falls back to index.html; browsers then reject registration
 * with a misleading "The operation is insecure" (Firefox) or a MIME-type error.
 */
async function assertServiceWorkerServed(): Promise<void> {
  let res: Response;
  try {
    res = await fetch("/sw.js", { cache: "no-store" });
  } catch {
    throw new Error("Could not fetch /sw.js — check your network / proxy.");
  }
  const type = (res.headers.get("content-type") || "").toLowerCase();
  if (!res.ok || !(type.includes("javascript") || type.includes("ecmascript"))) {
    throw new Error(
      `The service worker file /sw.js is not being served as JavaScript (HTTP ${res.status}, ${type || "no content-type"}). ` +
        "Make sure frontend/public/sw.js exists, rebuild the frontend, and that your reverse proxy forwards /sw.js to it.",
    );
  }
}

function explainRegistrationError(e: any): Error {
  const name = e?.name || "";
  const msg = String(e?.message || e || "");
  if (name === "SecurityError" || /insecure/i.test(msg)) {
    return new Error(
      "The browser refused to register the notification service worker (\"The operation is insecure\"). " +
        "This happens in private/incognito windows, when site data or cookies are blocked or cleared on exit " +
        "(Firefox: Settings → Privacy → allow cookies and site data for this site), or on a non-HTTPS address. " +
        "Open the app in a normal window over HTTPS and try again.",
    );
  }
  if (name === "NotAllowedError") return new Error("Notification permission was not granted.");
  if (name === "AbortError" || /push service/i.test(msg)) {
    return new Error(
      "The browser's push service rejected the subscription (" + (msg || name) + "). " +
        "Chromium builds without Google services (some Brave/Chromium installs) cannot use Web Push — try Chrome, Edge or Firefox.",
    );
  }
  return e instanceof Error ? e : new Error(msg || "Failed to subscribe to push notifications");
}

export async function subscribeToPush(): Promise<void> {
  if (!pushSupported()) throw new Error("Push notifications are not supported in this browser");

  if (!window.isSecureContext) {
    throw new Error(
      "Push requires a secure context (HTTPS or localhost). Open the app via its https:// address instead of a plain-HTTP IP.",
    );
  }

  await assertServiceWorkerServed();

  const permission = await Notification.requestPermission();
  if (permission !== "granted") throw new Error("Notification permission was not granted");

  let keyB64: string;
  try {
    keyB64 = (await endpoints.pushVapidPublicKey()).data.public_key;
  } catch (e: any) {
    throw new Error(
      e?.response?.status === 503
        ? "Web Push is not configured on the server (VAPID keys missing or invalid). See backend logs."
        : "Could not fetch the server's push key.",
    );
  }
  const appKey = urlBase64ToUint8Array(keyB64);

  try {
    const reg = await navigator.serviceWorker.register("/sw.js");
    await navigator.serviceWorker.ready;

    // A subscription made with a different server key (e.g. after rotating VAPID
    // keys) makes subscribe() throw InvalidStateError -- replace it.
    const existing = await reg.pushManager.getSubscription();
    if (existing && !sameKey(existing.options?.applicationServerKey, appKey)) {
      await existing.unsubscribe();
    }

    const subscription =
      (await reg.pushManager.getSubscription()) ||
      (await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: appKey.buffer as ArrayBuffer,
      }));

    const json = subscription.toJSON();
    await endpoints.pushSubscribe({
      endpoint: json.endpoint as string,
      keys: { p256dh: json.keys?.p256dh || "", auth: json.keys?.auth || "" },
      user_agent: navigator.userAgent,
    });
  } catch (e: any) {
    throw explainRegistrationError(e);
  }
}

export async function unsubscribeFromPush(): Promise<void> {
  const reg = await navigator.serviceWorker.getRegistration();
  if (!reg) return;
  const sub = await reg.pushManager.getSubscription();
  if (!sub) return;
  const endpoint = sub.endpoint;
  await sub.unsubscribe();
  try {
    await endpoints.pushUnsubscribe(endpoint);
  } catch {
    // best-effort -- browser-side unsubscribe already succeeded
  }
}

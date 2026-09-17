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

export async function subscribeToPush(): Promise<void> {
  if (!pushSupported()) throw new Error("Push notifications are not supported in this browser");
  
  if (!window.isSecureContext) {
    throw new Error("Push Manager requires a Secure Context (HTTPS or localhost). Accessing via an external IP over HTTP is blocked by the browser.");
  }

  const permission = await Notification.requestPermission();
  if (permission !== "granted") throw new Error("Notification permission was not granted");

  const { data } = await endpoints.pushVapidPublicKey();
  const reg = await navigator.serviceWorker.register("/sw.js");
  await navigator.serviceWorker.ready;

  const subscription = await reg.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array(data.public_key).buffer as ArrayBuffer,
  });

  const json = subscription.toJSON();
  await endpoints.pushSubscribe({
    endpoint: json.endpoint as string,
    keys: { p256dh: json.keys?.p256dh || "", auth: json.keys?.auth || "" },
    user_agent: navigator.userAgent,
  });
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
/*
 * NetSecAuditor push-notification service worker.
 *
 * This file is what makes Browser Push actually deliver anything.
 * lib/push.ts:subscribeToPush() calls navigator.serviceWorker.register("/sw.js")
 * before it ever subscribes to the PushManager — without a worker file at
 * that path the registration itself fails (404), so the whole channel was
 * unreachable regardless of how correct the backend VAPID/webpush code was.
 *
 * Kept intentionally small and dependency-free: this runs outside the
 * React bundle in its own worker context, no build step required. Vite
 * serves anything under /public/ at the site root, so this lands at
 * exactly the "/sw.js" path lib/push.ts registers.
 */

self.addEventListener("install", (event) => {
  // Activate immediately rather than waiting for all tabs to close, so a
  // freshly-deployed worker starts handling push events right away.
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("push", (event) => {
  let payload = { title: "NetSecAuditor alert", body: "", url: "/alerts" };
  try {
    if (event.data) {
      payload = { ...payload, ...event.data.json() };
    }
  } catch (e) {
    // alert_channel_service._send_push_to_subscription always sends JSON,
    // but never let a malformed/unexpected payload crash notification
    // display entirely — fall back to raw text if present.
    if (event.data) payload.body = event.data.text();
  }

  const title = payload.title || "NetSecAuditor alert";
  const options = {
    body: payload.body || "",
    icon: "/icon-192.png",
    badge: "/icon-192.png",
    data: { url: payload.url || "/alerts" },
    tag: payload.tag || "netsecauditor-alert",
    renotify: true,
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

// Clicking the OS notification focuses an already-open tab on this origin
// if one exists (navigating it to the alert's URL), otherwise opens a new
// one — the standard pattern so users land on the Alerts page instead of
// the notification just disappearing.
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.url) || "/alerts";

  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        const clientUrl = new URL(client.url);
        if (clientUrl.origin === self.location.origin && "focus" in client) {
          client.navigate(targetUrl);
          return client.focus();
        }
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow(targetUrl);
      }
    })
  );
});

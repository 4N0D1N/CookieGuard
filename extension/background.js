// CookieGuard - Background Service Worker (Manifest V3)
// Principio estricto de privacidad Zero-Trust: NUNCA almacena ni transmite valores de cookies.
// Únicamente supervisa metadatos: dominio, nombre, causa del cambio y timestamp.

const CRITICAL_DOMAINS = [
  "google.com", "github.com", "microsoft.com", "live.com",
  "okta.com", "amazon.com", "slack.com", "x.com"
];

chrome.cookies.onChanged.addListener((changeInfo) => {
  const cookie = changeInfo.cookie;
  if (!cookie) return;

  const domain = cookie.domain || "";
  const isCritical = CRITICAL_DOMAINS.some(d => domain.toLowerCase().includes(d));

  if (!isCritical) return;

  // Solo registrar si es una cookie de sesión (sin exp o larga duración) o típica de auth
  const isSessionCookie = !cookie.expirationDate || cookie.name.toLowerCase().includes("session") || cookie.name.includes("auth") || cookie.name.startsWith("__Host-");

  if (!isSessionCookie) return;

  const eventRecord = {
    timestamp: new Date().toISOString(),
    domain: domain,
    name: cookie.name,
    cause: changeInfo.cause, // "explicit", "overwrite", "expired", "evicted"
    removed: changeInfo.removed,
    secure: cookie.secure,
    httpOnly: cookie.httpOnly
  };

  chrome.storage.local.get({ events: [], criticalCount: 0 }, (data) => {
    const events = [eventRecord, ...data.events].slice(0, 50); // Últimos 50 eventos
    chrome.storage.local.set({ events });
  });

  // Actualizar badge visual
  if (changeInfo.removed) {
    chrome.action.setBadgeText({ text: "DEL" });
    chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
  } else {
    chrome.action.setBadgeText({ text: "OK" });
    chrome.action.setBadgeBackgroundColor({ color: "#10b981" });
  }
});

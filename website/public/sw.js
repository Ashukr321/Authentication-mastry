// Offline support: pages are network-first (fresh notes when online, cached copy when offline),
// static assets are cache-first (their URLs are content-hashed or rarely change).
const CACHE = "auth-mastery-v1";
const PRECACHE = ["/", "/manifest.webmanifest", "/icon.svg", "/icons/icon-192.png"];

self.addEventListener("install", (event) => {
    event.waitUntil(caches.open(CACHE).then((c) => c.addAll(PRECACHE)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
    event.waitUntil(
        caches
            .keys()
            .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
            .then(() => self.clients.claim()),
    );
});

const save = (request, response) => {
    if (response.ok) {
        const copy = response.clone();
        caches.open(CACHE).then((c) => c.put(request, copy));
    }
    return response;
};

self.addEventListener("fetch", (event) => {
    const { request } = event;
    const url = new URL(request.url);
    if (request.method !== "GET" || url.origin !== self.location.origin) return;

    const isStatic =
        url.pathname.startsWith("/_next/static/") ||
        url.pathname.startsWith("/icons/") ||
        url.pathname.startsWith("/content/resources/") ||
        /\.(?:svg|png|ico|woff2?)$/.test(url.pathname);

    if (isStatic) {
        event.respondWith(caches.match(request).then((hit) => hit || fetch(request).then((r) => save(request, r))));
        return;
    }

    // Pages, RSC payloads, diagrams and the search index
    event.respondWith(
        fetch(request)
            .then((r) => save(request, r))
            .catch(() =>
                caches
                    .match(request)
                    .then((hit) => hit || (request.mode === "navigate" ? caches.match("/") : Response.error())),
            ),
    );
});

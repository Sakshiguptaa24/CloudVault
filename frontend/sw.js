// CloudVault Service Worker - v1.0.0
// Strict Security Rule: NEVER cache /api/* responses, authentication tokens, or file payloads.

const CACHE_NAME = 'cloudvault-static-v1';

// Static Shell Assets only
const PRECACHE_ASSETS = [
    '/',
    '/static/css/styles.css',
    '/static/js/app.js',
    '/static/js/api.js',
    '/static/icons/icon.svg',
    '/static/icons/icon-192.png',
    '/static/icons/icon-512.png',
    '/manifest.json',
    '/offline.html'
];

// Install: Pre-cache application shell
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.addAll(PRECACHE_ASSETS);
        }).then(() => self.skipWaiting())
    );
});

// Activate: Clean up older caches
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) => {
            return Promise.all(
                keys.map((key) => {
                    if (key !== CACHE_NAME) {
                        return caches.delete(key);
                    }
                })
            );
        }).then(() => self.clients.claim())
    );
});

// Fetch: Strategy
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    // 1. STRICT SECURITY: Never intercept or cache API calls or non-GET requests
    if (url.pathname.startsWith('/api/') || event.request.method !== 'GET') {
        return; // Normal network pass-through
    }

    // 2. Navigation requests: Network-first with offline.html fallback
    if (event.request.mode === 'navigate') {
        event.respondWith(
            fetch(event.request).catch(() => {
                return caches.match('/offline.html');
            })
        );
        return;
    }

    // 3. Static assets: Cache-first with network fallback & stale-while-revalidate
    event.respondWith(
        caches.match(event.request).then((cachedResponse) => {
            if (cachedResponse) {
                // Fetch in background to update cache for next time
                fetch(event.request).then((networkResponse) => {
                    if (networkResponse && networkResponse.status === 200) {
                        caches.open(CACHE_NAME).then((cache) => {
                            cache.put(event.request, networkResponse);
                        });
                    }
                }).catch(() => { /* ignore background fetch errors */ });

                return cachedResponse;
            }

            return fetch(event.request).then((networkResponse) => {
                if (!networkResponse || networkResponse.status !== 200 || networkResponse.type !== 'basic') {
                    return networkResponse;
                }
                const responseToCache = networkResponse.clone();
                caches.open(CACHE_NAME).then((cache) => {
                    cache.put(event.request, responseToCache);
                });
                return networkResponse;
            }).catch(() => {
                if (event.request.destination === 'document') {
                    return caches.match('/offline.html');
                }
            });
        })
    );
});


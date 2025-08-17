const CACHE_NAME = 'nafij-social-v4';
const STATIC_CACHE = 'static-v4';
const DYNAMIC_CACHE = 'dynamic-v4';
const MEDIA_CACHE = 'media-v4';

// Static assets to cache
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/all.html',
  '/info.html',
  '/admin.html',
  '/style.css',
  '/manifest.json',
  '/icon.png'
];

// Install event - cache static assets
self.addEventListener('install', event => {
  console.log('Service Worker installing...');
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => {
        console.log('Caching static assets');
        return cache.addAll(STATIC_ASSETS);
      })
      .then(() => {
        console.log('Static assets cached');
        return self.skipWaiting();
      })
      .catch(error => {
        console.error('Error caching static assets:', error);
      })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
  console.log('Service Worker activating...');
  event.waitUntil(
    caches.keys()
      .then(cacheNames => {
        return Promise.all(
          cacheNames.map(cacheName => {
            if (!cacheName.includes('v4')) {
              console.log('Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            }
          })
        );
      })
      .then(() => {
        console.log('Service Worker activated');
        return self.clients.claim();
      })
  );
});

// Fetch event - handle requests with appropriate caching strategy
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests for caching
  if (request.method !== 'GET') {
    // Handle POST requests for offline sync
    if (request.method === 'POST' && url.pathname === '/api/posts') {
      event.respondWith(handleOfflinePost(request));
      return;
    }
    return;
  }

  // Handle API requests with network-first strategy
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkFirstStrategy(request));
    return;
  }

  // Handle media files with cache-first strategy and range support
  if (url.pathname.startsWith('/uploads/')) {
    event.respondWith(handleMediaRequest(request));
    return;
  }

  // Handle static assets with cache-first strategy
  if (STATIC_ASSETS.some(asset => url.pathname === asset || url.pathname.endsWith(asset))) {
    event.respondWith(cacheFirstStrategy(request));
    return;
  }

  // Handle navigation requests
  if (request.mode === 'navigate') {
    event.respondWith(
      networkFirstStrategy(request)
        .catch(() => caches.match('/index.html'))
    );
    return;
  }

  // Default: try network first, fallback to cache
  event.respondWith(networkFirstStrategy(request));
});

// Network-first strategy for API requests and dynamic content
async function networkFirstStrategy(request) {
  try {
    const networkResponse = await fetch(request);
    
    // Cache successful responses
    if (networkResponse.ok) {
      const cache = await caches.open(DYNAMIC_CACHE);
      // Don't cache POST responses
      if (request.method === 'GET') {
        cache.put(request, networkResponse.clone());
      }
    }
    
    return networkResponse;
  } catch (error) {
    console.log('Network failed, trying cache:', request.url);
    const cachedResponse = await caches.match(request);
    
    if (cachedResponse) {
      return cachedResponse;
    }
    
    // Return offline page for navigation requests
    if (request.mode === 'navigate') {
      return caches.match('/index.html');
    }
    
    throw error;
  }
}

// Cache-first strategy for static assets
async function cacheFirstStrategy(request) {
  const cachedResponse = await caches.match(request);
  
  if (cachedResponse) {
    return cachedResponse;
  }
  
  try {
    const networkResponse = await fetch(request);
    
    if (networkResponse.ok) {
      const cache = await caches.open(STATIC_CACHE);
      cache.put(request, networkResponse.clone());
    }
    
    return networkResponse;
  } catch (error) {
    console.error('Failed to fetch:', request.url, error);
    throw error;
  }
}

// Handle media requests with range support and caching
async function handleMediaRequest(request) {
  const cache = await caches.open(MEDIA_CACHE);
  const cachedResponse = await cache.match(request);
  
  // If we have a cached response and no range request, return it
  if (cachedResponse && !request.headers.get('range')) {
    return cachedResponse;
  }
  
  try {
    const networkResponse = await fetch(request);
    
    if (networkResponse.ok) {
      // Cache full responses (not range responses)
      if (networkResponse.status === 200 && !request.headers.get('range')) {
        cache.put(request, networkResponse.clone());
      }
    }
    
    return networkResponse;
  } catch (error) {
    // Return cached response if available
    if (cachedResponse) {
      return cachedResponse;
    }
    throw error;
  }
}

// Handle offline post submissions
async function handleOfflinePost(request) {
  try {
    // Try network first
    const response = await fetch(request);
    return response;
  } catch (error) {
    // Store for background sync
    const formData = await request.formData();
    const postData = {
      user: formData.get('user'),
      text: formData.get('text'),
      file: formData.get('file'),
      timestamp: Date.now()
    };
    
    await storeOfflinePost(postData);
    
    // Register background sync
    if ('serviceWorker' in navigator && 'sync' in window.ServiceWorkerRegistration.prototype) {
      await self.registration.sync.register('background-post');
    }
    
    // Return success response
    return new Response(JSON.stringify({ success: true, offline: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Background sync for offline posts
self.addEventListener('sync', event => {
  console.log('Background sync triggered:', event.tag);
  
  if (event.tag === 'background-post') {
    event.waitUntil(syncOfflinePosts());
  }
});

// Sync offline posts when connection is restored
async function syncOfflinePosts() {
  try {
    const offlinePosts = await getOfflinePosts();
    
    for (const post of offlinePosts) {
      try {
        const formData = new FormData();
        formData.append('user', post.user);
        formData.append('text', post.text);
        
        if (post.file) {
          formData.append('file', post.file);
        }
        
        const response = await fetch('/api/posts', {
          method: 'POST',
          body: formData
        });
        
        if (response.ok) {
          await removeOfflinePost(post.id);
        }
      } catch (error) {
        console.error('Error syncing post:', error);
      }
    }
    
    // Notify clients about sync completion
    const clients = await self.clients.matchAll();
    clients.forEach(client => {
      client.postMessage({
        type: 'SYNC_COMPLETE',
        message: `${offlinePosts.length} offline posts synced successfully`
      });
    });
    
  } catch (error) {
    console.error('Error syncing offline posts:', error);
  }
}

// IndexedDB operations for offline posts
async function openOfflineDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('OfflinePosts', 1);
    
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
    
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains('posts')) {
        const store = db.createObjectStore('posts', { keyPath: 'id', autoIncrement: true });
        store.createIndex('timestamp', 'timestamp', { unique: false });
      }
    };
  });
}

async function getOfflinePosts() {
  const db = await openOfflineDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(['posts'], 'readonly');
    const store = transaction.objectStore('posts');
    const request = store.getAll();
    
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function storeOfflinePost(postData) {
  const db = await openOfflineDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(['posts'], 'readwrite');
    const store = transaction.objectStore('posts');
    const request = store.add({
      ...postData,
      timestamp: Date.now()
    });
    
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

async function removeOfflinePost(id) {
  const db = await openOfflineDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(['posts'], 'readwrite');
    const store = transaction.objectStore('posts');
    const request = store.delete(id);
    
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

// Handle messages from the main thread
self.addEventListener('message', event => {
  const { data } = event;
  
  if (data && data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  
  if (data && data.type === 'GET_OFFLINE_COUNT') {
    getOfflinePosts().then(posts => {
      event.ports[0].postMessage({ count: posts.length });
    });
  }
});

// Push notification handling
self.addEventListener('push', event => {
  if (event.data) {
    const data = event.data.json();
    
    const options = {
      body: data.body || 'New activity on your post',
      icon: '/icon.png',
      badge: '/icon.png',
      vibrate: [100, 50, 100],
      data: {
        dateOfArrival: Date.now(),
        primaryKey: data.primaryKey || 1
      },
      actions: [
        {
          action: 'explore',
          title: 'View Post',
          icon: '/icon.png'
        },
        {
          action: 'close',
          title: 'Close',
          icon: '/icon.png'
        }
      ],
      tag: 'social-notification',
      renotify: true
    };
    
    event.waitUntil(
      self.registration.showNotification(data.title || 'Nafij\'s Social Share', options)
    );
  }
});

// Handle notification clicks
self.addEventListener('notificationclick', event => {
  event.notification.close();
  
  if (event.action === 'explore') {
    event.waitUntil(
      clients.matchAll().then(clientList => {
        if (clientList.length > 0) {
          return clientList[0].focus();
        }
        return clients.openWindow('/');
      })
    );
  }
});

// Periodic background sync for content updates
self.addEventListener('periodicsync', event => {
  if (event.tag === 'content-sync') {
    event.waitUntil(syncContent());
  }
});

async function syncContent() {
  try {
    const response = await fetch('/api/posts?limit=5');
    if (response.ok) {
      const posts = await response.json();
      
      // Cache new posts
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put('/api/posts?limit=5', new Response(JSON.stringify(posts)));
      
      // Notify clients of new content
      const clients = await self.clients.matchAll();
      clients.forEach(client => {
        client.postMessage({
          type: 'NEW_CONTENT',
          count: posts.length
        });
      });
    }
  } catch (error) {
    console.error('Error syncing content:', error);
  }
}

// Cache management
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'CLEAR_CACHE') {
    event.waitUntil(
      caches.keys().then(cacheNames => {
        return Promise.all(
          cacheNames.map(cacheName => caches.delete(cacheName))
        );
      })
    );
  }
});
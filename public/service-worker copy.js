// Instala o Service Worker e armazena os arquivos essenciais em cache
self.addEventListener('install', event => {
    event.waitUntil(
      caches.open('controle-frota-cache').then(cache => {
        return cache.addAll([
          '/',
          '/index.html',  // Alterado de index.ejs para index.html
          '/styles.css',
          '/app.js'       // Se app.js está na raiz e é servido como /app.js, está correto.
        ]);
      })
    );
  });
  
  // Intercepta as requisições e retorna o recurso do cache se disponível
  self.addEventListener('fetch', event => {
    event.respondWith(
      caches.match(event.request)
        .then(response => response || fetch(event.request))
    );
  });
  
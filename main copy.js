 //Código de registro do service worker (lembre: isso roda no browser!)
 if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/service-worker.js')
        .then(registration => {
          console.log('Service Worker registrado com sucesso:', registration.scope);
        })
        .catch(error => {
          console.error('Falha ao registrar o Service Worker:', error);
        });
    });
}
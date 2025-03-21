let deferredPrompt;

window.addEventListener('beforeinstallprompt', (event) => {
    console.log('Evento beforeinstallprompt capturado:', event);
    event.preventDefault(); // Impede o prompt automático do navegador
    console.log('Prompt padrão prevenido.');
    deferredPrompt = event; // Salva o evento para ser chamado depois
    console.log('Evento salvo em deferredPrompt.');

    // Exibe um botão na tela para o usuário instalar o PWA
    const installButton = document.createElement('button');
    installButton.innerText = 'Adicionar à Tela Inicial';
    installButton.style.position = 'fixed';
    installButton.style.bottom = '20px';
    installButton.style.left = '50%';
    installButton.style.transform = 'translateX(-50%)';
    installButton.style.padding = '10px 20px';
    installButton.style.background = '#007bff';
    installButton.style.color = 'white';
    installButton.style.border = 'none';
    installButton.style.borderRadius = '5px';
    installButton.style.cursor = 'pointer';
    installButton.style.zIndex = '1000';

    document.body.appendChild(installButton);
    console.log('Botão de instalação adicionado à página.');

    installButton.addEventListener('click', () => {
        console.log('Botão de instalação clicado.');
        installButton.style.display = 'none'; // Esconde o botão após o clique
        deferredPrompt.prompt(); // Exibe o prompt de instalação
        console.log('Prompt de instalação exibido.');

        deferredPrompt.userChoice.then((choiceResult) => {
            if (choiceResult.outcome === 'accepted') {
                console.log('Usuário aceitou instalar o PWA');
            } else {
                console.log('Usuário recusou instalar o PWA');
            }
            deferredPrompt = null; // Limpa o evento
            console.log('Evento deferredPrompt limpo.');
        });
    });
});

// Código de registro do service worker (roda no browser)
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

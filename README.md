# Sistema de Gerenciamento de Veículos

## Visão Geral

Esse sistema é um app de gerenciamento de frota feito em Node.js com Express e MySQL. Ele junta várias features: autenticação com Passport, controle de sessões, upload de imagens, registro e gerenciamento de veículos, controle de multas, recuperação de senha, notificações em tempo real. 
Cada usuário só vê o que tem permissão pra ver, com autorização por roles.

## Tecnologias

- **Node.js & Express:** Server e APIs REST.
- **MySQL:** Banco de dados relacional.
- **Passport:** Autenticação local com email e senha.
- **Express-session:** Gerenciamento de sessões.
- **Multer:** Upload de imagens.
- **Socket.IO:** Notificações em tempo real.
- **Nodemailer:** Envio de emails (pra reset de senha e alertas de manutenção).
- **EJS:** Renderizar as views.

## Funcionalidades

### Para Usuários Comuns

Depois de logar, o usuário comum pode:

- **Login/Logout:** Entrar e sair usando email e senha.
- **Recuperação de Senha:** Solicitar e resetar a senha via email.
- **Perfil:** Ver as próprias informações e o histórico de uso dos veículos.
- **Uso de Veículos:**
  - **Iniciar Uso:** Registrar o começo do uso, informando o motorista e o km inicial.
  - **Finalizar Uso (Edição de Uso):** Adicionar o km final, enviar a foto do odômetro e definir a data final.
- **Relatório de Uso:** Consultar um relatório paginado dos registros de uso, com detalhes sobre multas e outras infos.

### Para Administradores (Admin)

Os admins têm acesso a funções extras, como:

- **Registro de Veículos:** Adicionar novos veículos no sistema.
- **Edição/Exclusão de Veículos:** Atualizar e remover veículos cadastrados.
- **Gerenciamento de Uso de Veículos:**
  - Editar e excluir registros de uso.
  - Registrar, editar e excluir multas associadas.
- **Manutenção Preventiva:**
  - Receber alertas quando um veículo atingir 10.000 km depois da última troca de óleo.
  - Marcar que a troca foi feita, atualizando os dados do veículo.
- **Controle Total:** Acesso a todos os relatórios e funções administrativas.
- **Registrar Multa**

## Funcionalidades Extras

- **Notificações & Manutenção Preventiva:**  
  O sistema monitora o km dos veículos e, se a diferença entre o km atual e a última troca de óleo for igual ou maior que 10.000 km, manda uma notificação em tempo real via Socket.IO e dispara um email avisando que está na hora da manutenção.


- **Atualização de Localização via GPS:**  
  Uma rota específica recebe atualizações de localização (latitude e longitude) dos veículos, usando CORS pra permitir requisições de domínios específicos — ideal pra integração com apps de monitoramento.

- **Comunicação em Tempo Real:**  
  O Socket.IO é usado pra enviar notificações instantâneas (como a necessidade de troca de óleo) sem precisar recarregar a página.

## Como Rodar

### Setup do Ambiente

1. **Instalar Dependências:**  
   Rode `npm install` pra instalar todas as libs necessárias.

2. **Configurar Variáveis:**  
   Preencha o arquivo `.env` com os dados do banco, secret da sessão, credenciais de email, etc.

### Inicialização

1. **Banco de Dados:**  
   Garanta que o MySQL esteja rodando e que o DB (e as tabelas) estejam criados conforme esperado.

2. **Rodar o App:**  
   Execute `node app.js` ou `npm start` (conforme configurado no package.json).  
   Depois, acesse `http://localhost:3000` pra testar localmente.

### Testando

- Use o navegador pra acessar as páginas de login, perfil e demais funcionalidades de uso dos veículos.
- Adicione-o à tela inicial no seu mobile






## Sistema de Gerenciamento de Veículos
## Visão Geral

Este sistema é desenvolvido em Node.js utilizando o framework Express e conecta-se a um banco de dados MySQL para gerenciar o uso de veículos. 
Ele oferece funcionalidades de autenticação, controle de sessões, upload de imagens, registro de veículos, gerenciamento de multas e recuperação de senha. 
O acesso às funcionalidades é controlado por meio de autenticação (usando Passport) e autorização baseada em papéis (roles).

## Funcionalidades por Perfil de Usuário

## Usuário Comum
Após efetuar o login, o usuário comum tem acesso às seguintes funcionalidades:

Login/Logout: Acesso ao sistema com autenticação via email e senha.
Recuperação de Senha: Solicitação e redefinição de senha via email.
Perfil: Visualização das informações pessoais e dos registros de uso dos veículos.
Uso de Veículos:
Iniciar o uso de um veículo, informando dados como o motorista, quilometragem inicial.
Finalizar uso de um veículo através da Edição de uso: Adicionar km final, upload de imagem do odômetro final, Data final.
Relatório de Uso: Visualizar um relatório paginado do uso dos veículos, com informações sobre multas e outros detalhes.

## Usuário Administrador (Admin)
O usuário com role admin possui acesso a funcionalidades adicionais de gerenciamento, tais como:

Registro de Veículos: Cadastro de novos veículos no sistema.
Edição e Exclusão de Veículos: Atualização e remoção de veículos existentes.
Gerenciamento de Uso de Veículos:
Edição e exclusão de registros de uso dos veículos.
Registro, edição e exclusão de multas associadas ao uso dos veículos.

![Captura de tela 2025-02-27 122849](https://github.com/user-attachments/assets/1ff2e351-70f0-49de-9416-c2fc6e7e8dee)

![Captura de tela 2025-02-27 122859](https://github.com/user-attachments/assets/17b5d088-9465-4800-8542-1d299425e379)



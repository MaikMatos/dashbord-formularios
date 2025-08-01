# Sistema de Gestão de Sócios

![Badge do Projeto](https://img.shields.io/badge/status-completo-brightgreen)
![Tecnologias](https://img.shields.io/badge/tecnologias-Node.js%2C%20Express%2C%20MongoDB%2C%20HTML%2C%20CSS%2C%20JS-blueviolet)
![Licença](https://img.shields.io/badge/license-MIT-blue)

---

### 1. Visão Geral do Projeto

Este é um sistema full-stack para a gestão de sócios. A aplicação é dividida em dois componentes principais:

-   **Backend (API)**: Uma API RESTful construída com Node.js e Express, que se comunica com um banco de dados MongoDB. O backend gerencia todas as operações CRUD (Criar, Ler, Atualizar, Deletar) para os sócios e inclui um sistema de autenticação seguro com JWT (JSON Web Tokens).
-   **Frontend**: Uma interface de usuário simples em HTML, CSS e JavaScript que permite o cadastro de novos sócios e a visualização de todos os dados em uma dashboard administrativa.

### 2. Funcionalidades

-   **Autenticação de Usuário:** Registro e login de usuários para acesso seguro.
-   **API Protegida:** Todas as rotas sensíveis são protegidas por um middleware de autenticação JWT.
-   **Operações CRUD:**
    -   **C**riação de novos sócios.
    -   **R**eferência (leitura) de todos os sócios ou de um sócio específico.
    -   **U**pdate (atualização) de dados de sócios existentes.
    -   **D**elete (exclusão) de sócios.
-   **Dashboard Analítica:** Visualização de dados importantes como o total de sócios, salário médio por hora e média de dependentes.
-   **Validações:** Lógica de backend para evitar o cadastro de sócios duplicados por CPF ou e-mail.

### 3. Estrutura do Projeto

A estrutura de pastas e arquivos está organizada da seguinte forma:

.
├── backend.js               # Ponto de entrada do backend
├── package.json
├── package-lock.json
├── frontend/
│   ├── frontend.html        # Formulário de cadastro de sócios
│   └── panel.html           # Dashboard administrativa
├── config/
│   └── db.js                # Lógica de conexão com o MongoDB
├── controllers/
│   ├── authController.js    # Controladores para registro e login
│   └── socioController.js   # Controladores para CRUD de sócios
├── middleware/
│   └── authMiddleware.js    # Middleware para proteger rotas com JWT
├── models/
│   ├── Socio.js             # Modelo do Mongoose para os sócios
│   └── User.js              # Modelo do Mongoose para os usuários
├── routes/
│   ├── authRoutes.js        # Rotas da API para autenticação
│   └── socioRoutes.js       # Rotas da API para sócios
└── utils/
└── generateToken.js     # Função utilitária para gerar tokens JWT


### 4. Requisitos do Sistema

Certifique-se de ter os seguintes softwares instalados:
-   [Node.js](https://nodejs.org/) (versão 14 ou superior)
-   [MongoDB](https://www.mongodb.com/) (ou um serviço em nuvem como MongoDB Atlas)

### 5. Instalação e Execução

Siga estas instruções para rodar o projeto localmente:

1.  **Clone o repositório:**
    ```bash
    git clone [URL_DO_REPOSITORIO]
    cd [NOME_DO_REPOSITORIO]
    ```

2.  **Instale as dependências:**
    ```bash
    npm install
    ```

3.  **Configure o ambiente:**
    -   Crie um arquivo chamado `.env` na pasta raiz do projeto.
    -   Adicione as seguintes variáveis, substituindo os valores pelos seus:
    ```
    MONGO_URI=mongodb+srv://[SEU_USUARIO]:[SUA_SENHA]@[URL_DO_CLUSTER]?retryWrites=true&w=majority
    JWT_SECRET=suaChaveSecretaMuitoForte
    ```

4.  **Inicie o servidor:**
    ```bash
    node backend.js
    ```
    O servidor estará rodando em `http://localhost:5000`.

### 6. Como Usar

-   **API**: Você pode interagir com a API usando ferramentas como o Postman ou Insomnia. As rotas estão documentadas no arquivo `routes/`.
-   **Frontend**: Abra os arquivos `frontend.html` (para o formulário) e `panel.html` (para a dashboard) diretamente no seu navegador.
    -   **Importante**: O frontend precisa do token JWT para funcionar. Você deve obter o token através da rota de login (`/api/auth/login`) e salvá-lo no `localStorage` do navegador para que as requisições para a API funcionem.

---

# ... outras variáveis

# Configuração de E-mail (Exemplo com Gmail)
EMAIL_SERVICE=gmail
EMAIL_USER=seu-email@gmail.com
EMAIL_PASS=sua-senha-de-app-do-gmail
FRONTEND_URL=http://localhost:5000/frontend/resetPassword.html
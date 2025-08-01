/* backend-socios
├── node_modules/
├── .env                  (variáveis de ambiente)
├── server.js             (ponto de entrada da app)
├── package.json
├── package-lock.json
├── config/
│   └── db.js             (conexão com o banco de dados)
├── models/
│   ├── User.js           (modelo de usuário)
│   └── Socio.js          (modelo de sócio)
├── routes/
│   ├── authRoutes.js     (rotas de autenticação)
│   └── socioRoutes.js    (rotas de sócios)
├── controllers/
│   ├── authController.js (lógica de autenticação)
│   └── socioController.js(lógica para sócios)
├── middleware/
│   └── authMiddleware.js (middleware de proteção de rotas)
└── utils/
  └── generateToken.js  (função para gerar JWT) */

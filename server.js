const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const socioRoutes = require('./routes/socioRoutes');
const cors = require('cors'); // Para permitir requisições do seu frontend

dotenv.config(); // Carrega variáveis de ambiente do .env

connectDB(); // Conecta ao banco de dados

const app = express();

// Middleware para analisar o corpo das requisições JSON
app.use(express.json());

// Middleware para permitir CORS (Cross-Origin Resource Sharing)
// Essencial para seu frontend em HTML fazer requisições para este backend
app.use(cors());

// Rotas da API
app.use('/api/auth', authRoutes);
app.use('/api/socios', socioRoutes);

// Rota de teste
app.get('/', (req, res) => {
    res.send('API de Cadastro de Sócios está rodando...');
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
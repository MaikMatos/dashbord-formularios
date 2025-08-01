const express = require('express');
const {
    createOrUpdateSocio,
    getSocios,
    getSocioById,
    deleteSocio
} = require('../controllers/socioController');
const protect = require('../middleware/authMiddleware'); // Middleware para proteger as rotas
const router = express.Router();

// Rotas protegidas (exigem que o usuário esteja logado)
router.route('/').post(protect, createOrUpdateSocio).get(protect, getSocios);
router.route('/:id').get(protect, getSocioById).delete(protect, deleteSocio);


module.exports = router;
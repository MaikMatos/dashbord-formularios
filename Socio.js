const mongoose = require('mongoose');

const SocioSchema = new mongoose.Schema({
    nome: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    telefone: { type: String, required: true },
    dataNascimento: { type: Date, required: true },
    endereco: { type: String, required: true },
    cpf: { type: String, required: true, unique: true },
    rg: { type: String, required: true },
    carteiraTrabalho: { type: String, required: true },
    registroEmpresa: { type: String, required: true },
    empresaTrabalha: { type: String, required: true },
    tempoEmpresa: { type: Number, required: true },
    salarioHora: { type: Number, required: true },
    dataVirouSocio: { type: Date, required: true },
    dependentes: { type: Number, required: true },
    linkSite: { type: String },
    // Adicionar referência ao usuário que criou/atualizou o sócio (opcional, mas bom para auditoria)
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Socio', SocioSchema);
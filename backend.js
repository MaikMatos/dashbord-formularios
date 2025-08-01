const Socio = require('../models/Socio');

// @desc    Cadastrar/Atualizar Sócio
// @route   POST /api/socios
// @access  Private
const createOrUpdateSocio = async (req, res) => {
    const {
        nome, email, telefone, dataNascimento, endereco, cpf, rg,
        carteiraTrabalho, registroEmpresa, empresaTrabalha, tempoEmpresa,
        salarioHora, dataVirouSocio, dependentes, linkSite
    } = req.body;

    try {
        // Tenta encontrar um sócio existente pelo CPF para atualização
        let socio = await Socio.findOne({ cpf });

        if (socio) {
            // Atualizar sócio existente
            socio.nome = nome || socio.nome;
            socio.email = email || socio.email;
            socio.telefone = telefone || socio.telefone;
            socio.dataNascimento = dataNascimento || socio.dataNascimento;
            socio.endereco = endereco || socio.endereco;
            socio.rg = rg || socio.rg;
            socio.carteiraTrabalho = carteiraTrabalho || socio.carteiraTrabalho;
            socio.registroEmpresa = registroEmpresa || socio.registroEmpresa;
            socio.empresaTrabalha = empresaTrabalha || socio.empresaTrabalha;
            socio.tempoEmpresa = tempoEmpresa || socio.tempoEmpresa;
            socio.salarioHora = salarioHora || socio.salarioHora;
            socio.dataVirouSocio = dataVirouSocio || socio.dataVirouSocio;
            socio.dependentes = dependentes || socio.dependentes;
            socio.linkSite = linkSite || socio.linkSite;
            socio.updatedAt = Date.now();

            await socio.save();
            res.status(200).json({ message: 'Sócio atualizado com sucesso!', socio });
        } else {
            // Criar novo sócio
            socio = new Socio({
                nome, email, telefone, dataNascimento, endereco, cpf, rg,
                carteiraTrabalho, registroEmpresa, empresaTrabalha, tempoEmpresa,
                salarioHora, dataVirouSocio, dependentes, linkSite,
                createdBy: req.user._id // Quem criou este sócio (do token JWT)
            });
            await socio.save();
            res.status(201).json({ message: 'Sócio cadastrado com sucesso!', socio });
        }

    } catch (error) {
        console.error(error);
        // Erro de validação ou email/cpf duplicado (se já existir um sem ser o que está sendo atualizado)
        if (error.code === 11000) { // Código de erro para duplicidade de chave única no MongoDB
            return res.status(400).json({ message: 'Email ou CPF já cadastrado.' });
        }
        res.status(500).json({ message: 'Erro ao processar o sócio.' });
    }
};

// @desc    Obter todos os sócios
// @route   GET /api/socios
// @access  Private
const getSocios = async (req, res) => {
    try {
        const socios = await Socio.find({}); // Pode adicionar paginação, filtros, etc. aqui
        res.json(socios);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro ao buscar sócios.' });
    }
};

// @desc    Obter sócio por ID
// @route   GET /api/socios/:id
// @access  Private
const getSocioById = async (req, res) => {
    try {
        const socio = await Socio.findById(req.params.id);

        if (socio) {
            res.json(socio);
        } else {
            res.status(404).json({ message: 'Sócio não encontrado.' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro ao buscar sócio.' });
    }
};

// @desc    Deletar sócio
// @route   DELETE /api/socios/:id
// @access  Private
const deleteSocio = async (req, res) => {
    try {
        const socio = await Socio.findById(req.params.id);

        if (socio) {
            await socio.deleteOne(); // Use deleteOne() ou deleteMany()
            res.json({ message: 'Sócio removido.' });
        } else {
            res.status(404).json({ message: 'Sócio não encontrado.' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro ao remover sócio.' });
    }
};


module.exports = {
    createOrUpdateSocio,
    getSocios,
    getSocioById,
    deleteSocio
};
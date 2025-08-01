const User = require('../models/User');
const generateToken = require('../utils/generateToken');
const sendEmail = require('../utils/sendEmail');
const crypto = require('crypto');

// @desc    Registrar novo usuário
// @route   POST /api/auth/register
// @access  Public
const registerUser = async (req, res) => {
    const { cpf, password, email } = req.body;

    try {
        const userExists = await User.findOne({ cpf });
        if (userExists) {
            return res.status(400).json({ message: 'Usuário com este CPF já existe' });
        }

        const user = await User.create({
            cpf,
            password,
            email
        });

        if (user) {
            res.status(201).json({
                _id: user._id,
                cpf: user.cpf,
                email: user.email,
                token: generateToken(user._id)
            });
        } else {
            res.status(400).json({ message: 'Dados de usuário inválidos' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro no servidor' });
    }
};

// @desc    Autenticar usuário com CPF e obter token
// @route   POST /api/auth/login
// @access  Public
const authUser = async (req, res) => {
    const { cpf, password } = req.body;

    try {
        const user = await User.findOne({ cpf });

        if (user && (await user.matchPassword(password))) {
            res.json({
                _id: user._id,
                cpf: user.cpf,
                token: generateToken(user._id)
            });
        } else {
            res.status(401).json({ message: 'CPF ou senha inválidos' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro no servidor' });
    }
};

// @desc    Solicitar redefinição de senha
// @route   POST /api/auth/forgotpassword
// @access  Public
const forgotPassword = async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'E-mail não encontrado.' });
        }

        const resetToken = user.getResetPasswordToken();
        await user.save({ validateBeforeSave: false });

        const resetUrl = `http://localhost:5000/frontend/resetPassword.html?token=${resetToken}`;

        const message = `
            <h1>Você solicitou a redefinição de senha</h1>
            <p>Por favor, acesse o link abaixo para redefinir sua senha:</p>
            <a href=${resetUrl} clicktracking=off>${resetUrl}</a>
        `;

        try {
            await sendEmail({
                email: user.email,
                subject: 'Redefinição de Senha',
                message
            });

            res.status(200).json({ message: 'E-mail enviado' });
        } catch (error) {
            console.error(error);
            user.resetPasswordToken = undefined;
            user.resetPasswordExpire = undefined;
            await user.save({ validateBeforeSave: false });

            res.status(500).json({ message: 'Erro ao enviar o e-mail de redefinição.' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro no servidor' });
    }
};

// @desc    Redefinir senha com token
// @route   PUT /api/auth/resetpassword/:resettoken
// @access  Public
const resetPassword = async (req, res) => {
    const resetPasswordToken = crypto
        .createHash('sha256')
        .update(req.params.resettoken)
        .digest('hex');

    try {
        const user = await User.findOne({
            resetPasswordToken,
            resetPasswordExpire: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Token inválido ou expirado.' });
        }

        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;
        await user.save();

        res.status(200).json({ message: 'Senha redefinida com sucesso!' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro no servidor' });
    }
};

module.exports = { registerUser, authUser, forgotPassword, resetPassword };
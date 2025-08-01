const mongoose = require('mongoose');
require('dotenv').config();

const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            // useCreateIndex: true, // Deprecated em Mongoose 6.x+
            // useFindAndModify: false // Deprecated em Mongoose 6.x+
        });
        console.log('MongoDB Conectado...');
    } catch (err) {
        console.error(err.message);
        process.exit(1); // Sai do processo com falha
    }
};

module.exports = connectDB;
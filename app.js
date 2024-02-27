require('dotenv').config();
const express = require('express');
const { sequelize, User } = require('./models');
const bcrypt = require('bcryptjs');
const basicAuth = require('basic-auth');

const app = express();
app.use(express.json());

const authMiddleware = async (req, res, next) => {
    const userCredentials = basicAuth(req);
    if (!userCredentials) {
        return res.status(401).json({ message: 'Authentication required.' });
    }

    try {
        const user = await User.findOne({ where: { email: userCredentials.name } });
        if (!user) {
            return res.status(401).json({ message: 'Authentication failed.' });
        }

        const passwordValid = await bcrypt.compare(userCredentials.pass, user.password);
        if (!passwordValid) {
            return res.status(401).json({ message: 'Authentication failed.' });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(500).json({ message: 'Internal server error.' });
    }
};

// Endpoint for creating a new user
app.post('/users', async (req, res) => {
    const { firstName, lastName, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ firstName, lastName, email, password: hashedPassword });
        return res.status(201).json({ id: user.id, email: user.email, firstName: user.firstName, lastName: user.lastName });
    } catch (error) {
        if (error.name === 'SequelizeUniqueConstraintError') {
            return res.status(400).json({ message: 'Email already exists.' });
        }
        return res.status(500).json({ message: 'Could not create user.' });
    }
});

// Endpoint for updating an existing user's information
app.put('/users/:id', authMiddleware, async (req, res) => {
    if (req.params.id != req.user.id) {
        return res.status(403).json({ message: 'You can only update your own information.' });
    }

    const { firstName, lastName, password } = req.body;
    try {
        const hashedPassword = password ? await bcrypt.hash(password, 10) : req.user.password;
        await User.update({ firstName, lastName, password: hashedPassword }, { where: { id: req.user.id } });
        return res.status(204).send();
    } catch (error) {
        return res.status(400).json({ message: 'Could not update user.' });
    }
});

// Endpoint for retrieving a user's information
app.get('/users/:id', authMiddleware, async (req, res) => {
    if (req.params.id != req.user.id) {
        return res.status(403).json({ message: 'You can only access your own information.' });
    }

    try {
        // Exclude the password from the response
        const user = await User.findByPk(req.user.id, {
            attributes: { exclude: ['password'] }
        });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        return res.json(user);
    } catch (error) {
        return res.status(500).json({ message: 'Internal server error.' });
    }
});

// Health Check Endpoint
app.get('/healthz', (req, res) => {
    res.status(200).send('OK');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    console.log(`Server running on port ${PORT}`);
    try {
        await sequelize.sync(); // This line is crucial for bootstrapping the database on app start
        console.log('Database connected and synced!');
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
});

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());
const PORT = 2000;

// In-memory user storage (replace with a database in real-world)
const users = [];

const SECRET_KEY = "your_jwt_secret_key";

// Register User
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.json({ message: 'User registered successfully' });
});

// Login User
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
});

// Protected Route
app.get('/api/protected', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(403).json({ message: 'Access denied' });

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        res.json({ message: `Welcome, ${decoded.username}` });
    } catch {
        res.status(403).json({ message: 'Invalid token' });
    }
});

app.listen(PORT, () => {
    console.log(`Auth Service running on port ${PORT}`);
});
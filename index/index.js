// Title: Simple User Authentication API in Node.js (100 Lines)

// Required modules
const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');



app.use(express.json());

const PORT = 3000;
const SECRET_KEY = 'mySecretKey';

// In-memory user database (for demo purposes only)
let users = [];

// Helper function to generate JWT token
function generateToken(user) {
    return jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
}

// Register new user
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    const existingUser = users.find(user => user.username === username);
    if (existingUser) {
        return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { username, password: hashedPassword };

    users.push(newUser);

    res.status(201).json({ message: 'User registered successfully' });
});

// Login user
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(user => user.username === username);
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = generateToken(user);
    res.json({ message: 'Login successful', token });
});

// Middleware for token verification
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
}

// Protected route (example)
app.get('/profile', authenticateToken, (req, res) => {
    const user = users.find(u => u.username === req.user.username);
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'Profile data', username: user.username });
});

// Logout (simple client-side token discard example)
app.post('/logout', (req, res) => {
    res.json({ message: 'Logged out. Please discard the token on the client side.' });
});

// Admin-only route (optional example)
app.get('/users', authenticateToken, (req, res) => {
    res.json(users.map(u => ({ username: u.username })));
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});

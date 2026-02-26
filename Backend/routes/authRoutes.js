const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// Inline middleware (so we don't need external file)
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

// REGISTER
router.post('/register', async (req, res) => {
    const { fullName, email, password, role } = req.body;
    
    if (!fullName || !email || !password || !role) {
        return res.status(400).json({ success: false, message: 'All fields required' });
    }
    
    const validRoles = ['Admin', 'Registrar', 'Instructor', 'Student'];
    if (!validRoles.includes(role)) {
        return res.status(400).json({ success: false, message: 'Invalid role' });
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        // TODO: Insert into database
        
        res.status(201).json({ success: true, message: 'User registered' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error registering user' });
    }
});

// LOGIN - Simple test version
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password required' });
    }
    
    // Accept any login for testing
    // Map email to role
    let role = 'Student';
    let fullName = 'Test User';
    
    if (email.includes('admin')) {
        role = 'Admin';
        fullName = 'Admin User';
    } else if (email.includes('registrar')) {
        role = 'Registrar';
        fullName = 'Registrar User';
    } else if (email.includes('instructor')) {
        role = 'Instructor';
        fullName = 'Instructor User';
    }
    
    const token = jwt.sign(
        { id: 1, email: email, role: role },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
    
    res.json({ 
        success: true, 
        token, 
        message: 'Login successful', 
        user: { id: 1, fullName: fullName, email: email, role: role } 
    });
});

// PROFILE (Protected)
router.get('/profile', authMiddleware, (req, res) => {
    res.json({ success: true, user: req.user });
});

module.exports = router;
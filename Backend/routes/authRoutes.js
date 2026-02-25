const express = require('express');
const router = express.Router();

// LOGIN
router.post('/login', (req, res) => {
    const { email, password } = req.body;

    res.json({
        message: "Login route working",
        email: email
    });
});

// REGISTER
router.post('/register', (req, res) => {
    res.status(201).json({
        message: "Register route working",
        data: req.body
    });
});

module.exports = router;
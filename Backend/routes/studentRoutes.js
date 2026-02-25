const express = require('express');
const router = express.Router();

// GET all students
router.get('/', (req, res) => {
    res.json({
        message: "GET all students working"
    });
});

// GET single student by ID
router.get('/:id', (req, res) => {
    const { id } = req.params;

    res.json({
        message: `GET student with ID ${id}`
    });
});

// CREATE new student
router.post('/', (req, res) => {
    const studentData = req.body;

    res.status(201).json({
        message: "Student created successfully",
        data: studentData
    });
});

// UPDATE student
router.put('/:id', (req, res) => {
    const { id } = req.params;
    const updatedData = req.body;

    res.json({
        message: `Student ${id} updated`,
        data: updatedData
    });
});

// DELETE student
router.delete('/:id', (req, res) => {
    const { id } = req.params;

    res.json({
        message: `Student ${id} deleted`
    });
});

module.exports = router;
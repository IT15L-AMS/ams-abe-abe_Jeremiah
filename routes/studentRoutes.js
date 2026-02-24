const express = require('express');
const router = express.Router();
const studentController = require('../controllers/studentController');
const authMiddleware = require('../middleware/authMiddleware');

// All routes require authentication
router.use(authMiddleware);

// GET all students
router.get('/', studentController.getAllStudents);

// GET single student by ID
router.get('/:id', studentController.getStudentById);

// POST create new student (Admin/Registrar only)
router.post('/', studentController.createStudent);

// PUT update student by ID
router.put('/:id', studentController.updateStudent);

// DELETE student by ID
router.delete('/:id', studentController.deleteStudent);

module.exports = router;
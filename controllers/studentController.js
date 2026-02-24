const pool = require('../config/database');

// GET all students
const getAllStudents = async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM students ORDER BY created_at DESC'
    );
    
    res.json({
      success: true,
      count: rows.length,
      data: rows
    });
  } catch (err) {
    console.error('Error fetching students:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch students',
      error: err.message
    });
  }
};

// GET single student by ID
const getStudentById = async (req, res) => {
  try {
    const { id } = req.params;
    
    const [rows] = await pool.query(
      'SELECT * FROM students WHERE id = ?',
      [id]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Student not found'
      });
    }
    
    res.json({
      success: true,
      data: rows[0]
    });
  } catch (err) {
    console.error('Error fetching student:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch student',
      error: err.message
    });
  }
};

// POST create new student
const createStudent = async (req, res) => {
  try {
    const { name, course, year } = req.body;
    
    // Validation
    if (!name || !course || !year) {
      return res.status(400).json({
        success: false,
        message: 'Missing name, course, or year'
      });
    }
    
    const [result] = await pool.query(
      `INSERT INTO students (name, course, year) VALUES (?, ?, ?)`,
      [name, course, year]
    );
    
    res.status(201).json({
      success: true,
      message: 'Student created successfully',
      data: { id: result.insertId, name, course, year }
    });
  } catch (err) {
    console.error('Error creating student:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to create student',
      error: err.message
    });
  }
};

// PUT update student by ID
const updateStudent = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, course, year } = req.body;
    
    // Validation
    if (!name || !course || !year) {
      return res.status(400).json({
        success: false,
        message: 'Missing name, course, or year'
      });
    }
    
    // Check if student exists
    const [checkRows] = await pool.query(
      'SELECT * FROM students WHERE id = ?',
      [id]
    );
    
    if (checkRows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Student not found'
      });
    }
    
    await pool.query(
      `UPDATE students SET name = ?, course = ?, year = ? WHERE id = ?`,
      [name, course, year, id]
    );
    
    // Fetch updated record
    const [updatedRows] = await pool.query(
      'SELECT * FROM students WHERE id = ?',
      [id]
    );
    
    res.json({
      success: true,
      message: 'Student updated successfully',
      data: updatedRows[0]
    });
  } catch (err) {
    console.error('Error updating student:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to update student',
      error: err.message
    });
  }
};

// DELETE student by ID
const deleteStudent = async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if student exists
    const [checkRows] = await pool.query(
      'SELECT * FROM students WHERE id = ?',
      [id]
    );
    
    if (checkRows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Student not found'
      });
    }
    
    await pool.query(
      'DELETE FROM students WHERE id = ?',
      [id]
    );
    
    res.json({
      success: true,
      message: 'Student deleted successfully'
    });
  } catch (err) {
    console.error('Error deleting student:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to delete student',
      error: err.message
    });
  }
};

module.exports = {
  getAllStudents,
  getStudentById,
  createStudent,
  updateStudent,
  deleteStudent
};
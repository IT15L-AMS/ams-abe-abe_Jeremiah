# API Documentation - Authentication Module

## Base URL
http://localhost:3000/api/auth

## POST /register

Description: Register a new user

Headers:

Key: Content-type
Value: application/json

## Request Body:

{
  "fullName": "John Doe",
  "email": "john@test.com",
  "password": "password123",
  "role": "Student"
}

Valid Roles: Admin, Registrar, Instructor, Student

## Success Response (201):

{
  "success": true,
  "message": "User registered successfully"
}

## Error Response (400):

{
  "success": false,
  "message": "Email already registered"
}

Authentication Required: No

## POST /login
Description: Authenticate user and get access token
Headers:

key: Content-Type
Value: application/json

Request Body:
{
  "email": "admin@ams.edu",
  "password": "password123"
}

Success Response (200):
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "message": "Login successful",
  "user": {
    "id": 1,
    "fullName": "Admin User",
    "email": "admin@ams.edu",
    "role": "Admin"
  }
}

Error Response (401):
{
  "success": false,
  "message": "Invalid credentials"
}
Authentication Required: No

## Get/profile
Description: Get current user profile (Protected Route)
Headers:

key:
    Content-Type
    Authorization

Value:
    Application/json
    Bearer <token>

Success Response(200):
{
  "success": true,
  "user": {
    "id": 1,
    "email": "admin@ams.edu",
    "role": "Admin"
  }
}

Error Response(401):
{
  "success": false,
  "message": "No token provided. Access denied."
}

Authentication Required: Yes

Role Permissions
Role:
   Admin
   Registrar
   Instructor
   Student

Access Level:
    Full System Access
    Manage student records
    Manage attendance & grades
    View own attendance & grades

Summary Table:
    Endpoint:
        /register
        /login
        /profile

    Method:
        POST
        POST
        GET

    Auth Required:
        No
        No
        Yes

    Description:
        Register new user
        Login and get token
        Get user profile


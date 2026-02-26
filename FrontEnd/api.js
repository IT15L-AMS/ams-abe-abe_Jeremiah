// handles API calls
const API_URL = "http://localhost:3000";

async function registerUser(userData) {
    const res = await fetch(`${API_URL}/api/auth/register`, {  // Changed from /auth to /api/auth
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(userData)
    });
    return res.json();
}

async function loginUser(userData) {
    const res = await fetch(`${API_URL}/api/auth/login`, {  // Changed from /auth to /api/auth
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(userData)
    });
    return res.json();
}

async function getProfile() {
    const token = localStorage.getItem("token");
    const res = await fetch(`${API_URL}/api/auth/profile`, {  // Changed from /auth to /api/auth
        method: "GET",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`
        }
    });
    return res.json();
}
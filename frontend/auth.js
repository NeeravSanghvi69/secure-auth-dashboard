const API_BASE = "http://localhost:3000";

// =======================
// AUTH CHECK (for protected pages)
// =======================
function checkAuth() {
  const token = localStorage.getItem("token");
  if (!token) {
    window.location.href = "login.html";
  }
  return token;
}

// =======================
// LOGIN
// =======================
function login() {
  fetch(`${API_BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: document.getElementById("username").value,
      password: document.getElementById("password").value
    })
  })
  .then(res => res.json())
  .then(data => {
    if (data.token) {
      localStorage.setItem("token", data.token);
      window.location.href = "dashboard.html";
    } else {
      document.getElementById("result").innerText = data.message;
    }
  })
  .catch(() => {
    document.getElementById("result").innerText = "Server error";
  });
}

// =======================
// LOAD USERS (JWT PROTECTED)
// =======================
function loadUsers() {
  const token = checkAuth();

  fetch(`${API_BASE}/users`, {
    headers: {
      "Authorization": "Bearer " + token
    }
  })
  .then(res => {
    if (res.status === 401 || res.status === 403) {
      logout();
    }
    return res.json();
  })
  .then(data => {
    document.getElementById("output").innerText =
      JSON.stringify(data, null, 2);
  });
}

// =======================
// LOGOUT
// =======================
function logout() {
  localStorage.removeItem("token");
  window.location.href = "login.html";
}

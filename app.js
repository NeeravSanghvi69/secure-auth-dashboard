require("dotenv").config({ path: "./.env" });

const express = require('express');
const mysql2 = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;

const app = express();
const port = 3000;

app.use(cors());
app.use(bodyParser.json());

// =======================
// In-memory refresh token store
// =======================
let refreshTokens = [];

// =======================
// MySQL connection
// =======================
const connection = mysql2.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Nicksan456',
    database: 'smart'
});

connection.connect((err) => {
    if (err) {
        console.error("MySQL connection failed:", err.message);
        return;
    }
    console.log('Connected to MySQL Server!');
});

// =======================
// JWT AUTH MIDDLEWARE
// =======================
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(401).json({ message: "Token required" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid token" });
        req.user = user;
        next();
    });
}

// =======================
// ROLE AUTHORIZATION
// =======================
function authorizeRole(role) {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ message: "Access denied" });
        }
        next();
    };
}

// =======================
// PREVENT SELF ACTION
// =======================
function preventSelfAction(req, res, next) {
    if (req.user.id == req.params.id) {
        return res.status(403).json({ message: "Cannot perform this action on yourself" });
    }
    next();
}

// =======================
// AUDIT LOGGER
// =======================
function logAudit(adminId, action, targetUserId) {
    const sql = `
        INSERT INTO audit_logs (admin_id, action, target_user_id)
        VALUES (?, ?, ?)
    `;
    connection.query(sql, [adminId, action, targetUserId]);
}

// =======================
// Root route
// =======================
app.get("/", (req, res) => {
    res.send("Smart App Backend is running 🚀");
});

// =======================
// REGISTER
// =======================
app.post("/users", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password)
        return res.status(400).json({ message: "Username and password required" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = "INSERT INTO users (username, password) VALUES (?, ?)";
    connection.query(sql, [username, hashedPassword], (err, result) => {
        if (err) return res.status(500).json({ message: "User creation failed" });

        res.json({ message: "User registered successfully", userId: result.insertId });
    });
});

// =======================
// LOGIN
// =======================
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    const sql = "SELECT * FROM users WHERE username = ? AND is_deleted = false";
    connection.query(sql, [username], async (err, results) => {
        if (err || results.length === 0)
            return res.status(401).json({ message: "Invalid credentials" });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch)
            return res.status(401).json({ message: "Invalid credentials" });

        const accessToken = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: "15m" }
        );

        const refreshToken = jwt.sign(
            { id: user.id },
            REFRESH_SECRET,
            { expiresIn: "7d" }
        );

        refreshTokens.push(refreshToken);

        res.json({ message: "Login successful", accessToken, refreshToken });
    });
});

// =======================
// REFRESH TOKEN
// =======================
app.post("/token", (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken || !refreshTokens.includes(refreshToken))
        return res.sendStatus(403);

    jwt.verify(refreshToken, REFRESH_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);

        const sql = "SELECT id, username, role FROM users WHERE id = ?";
        connection.query(sql, [user.id], (err, results) => {
            if (err || results.length === 0) return res.sendStatus(403);

            const dbUser = results[0];

            const accessToken = jwt.sign(
                { id: dbUser.id, username: dbUser.username, role: dbUser.role },
                JWT_SECRET,
                { expiresIn: "15m" }
            );

            res.json({ accessToken });
        });
    });
});

// =======================
// USERS (PROTECTED)
// =======================
app.get('/users', authenticateToken, (req, res) => {
    const sql = 'SELECT id, username, role FROM users WHERE is_deleted = false';
    connection.query(sql, (err, results) => {
        if (err) return res.status(500).send("Database error");
        res.send(results);
    });
});

// =======================
// ADMIN: LIST USERS
// =======================
app.get('/admin/users',
    authenticateToken,
    authorizeRole("admin"),
    (req, res) => {
        const sql = "SELECT id, username, role, is_deleted FROM users";
        connection.query(sql, (err, results) => {
            if (err) return res.sendStatus(500);
            res.json(results);
        });
    }
);

// =======================
// ADMIN: PROMOTE USER
// =======================
app.put('/admin/promote/:id',
    authenticateToken,
    authorizeRole("admin"),
    preventSelfAction,
    (req, res) => {
        const sql = "UPDATE users SET role='admin' WHERE id=?";
        connection.query(sql, [req.params.id], (err, result) => {
            if (err || result.affectedRows === 0)
                return res.sendStatus(404);

            logAudit(req.user.id, "PROMOTE_USER", req.params.id);
            res.json({ message: "User promoted to admin" });
        });
    }
);

// =======================
// ADMIN: SOFT DELETE USER
// =======================
app.delete('/admin/users/:id',
    authenticateToken,
    authorizeRole("admin"),
    preventSelfAction,
    (req, res) => {
        const sql = "UPDATE users SET is_deleted=true WHERE id=?";
        connection.query(sql, [req.params.id], (err, result) => {
            if (err || result.affectedRows === 0)
                return res.sendStatus(404);

            logAudit(req.user.id, "SOFT_DELETE_USER", req.params.id);
            res.json({ message: "User soft deleted" });
        });
    }
);

// =======================
// ADMIN: CREATE USER
// =======================
app.post('/admin/users',
    authenticateToken,
    authorizeRole("admin"),
    async (req, res) => {
        const { username, password, role } = req.body;
        const hashed = await bcrypt.hash(password, 10);

        const sql = "INSERT INTO users (username, password, role) VALUES (?, ?, ?)";
        connection.query(sql, [username, hashed, role || 'user'], () => {
            logAudit(req.user.id, "CREATE_USER", null);
            res.json({ message: "User created" });
        });
    }
);

// =======================
// ADMIN: AUDIT LOGS
// =======================
app.get('/admin/audit-logs',
    authenticateToken,
    authorizeRole("admin"),
    (req, res) => {
        connection.query("SELECT * FROM audit_logs ORDER BY created_at DESC", (err, logs) => {
            if (err) return res.sendStatus(500);
            res.json(logs);
        });
    }
);

// =======================
// Start server
// =======================
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

// backend/server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

// MySQL connection pool
const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "176969", // your MySQL password
  database: "task_manager",
  waitForConnections: true,
  connectionLimit: 10,
});



// Test connection
(async () => {
  try {
    const conn = await pool.getConnection();
    console.log("✅ MySQL connected");
    conn.release();
  } catch (err) {
    console.error("❌ MySQL error:", err.message);
  }
})();


// Helper to generate JWT
const generateToken = (userId) => {
  return jwt.sign({ userId }, "your_secret_key", { expiresIn: "7d" });
};


// ---------- AUTH MIDDLEWARE ----------
const auth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "No token provided" });
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, "your_secret_key");
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
};


// ---------- REGISTER ----------
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      "INSERT INTO users (email, password) VALUES (?, ?)",
      [email, hashedPassword],
    );
    res.status(201).json({ message: "User created", userId: result.insertId });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      res.status(400).json({ error: "Email already exists" });
    } else {
      console.error(err);
      res.status(500).json({ error: "Server error" });
    }
  }
});

// ---------- LOGIN ----------
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required" });
  }
  try {
    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = generateToken(user.id);
    res.json({ token, userId: user.id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------- TASK ENDPOINTS (PROTECTED) ----------


// Create a task
app.post("/api/tasks", auth, async (req, res) => {
  const { title, description } = req.body;
  if (!title) return res.status(400).json({ error: "Title is required" });
  try {
    const [result] = await pool.query(
      "INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)",
      [req.userId, title, description || null],
    );
    res
      .status(201)
      .json({ id: result.insertId, title, description, is_complete: false });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create task" });
  }
});

// Get all tasks for logged-in user
app.get("/api/tasks", auth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC",
      [req.userId],
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch tasks" });
  }
});


// Update a task (toggle complete)
app.put("/api/tasks/:id", auth, async (req, res) => {
  const { is_complete } = req.body;
  const taskId = req.params.id;
  try {
    await pool.query(
      "UPDATE tasks SET is_complete = ? WHERE id = ? AND user_id = ?",
      [is_complete, taskId, req.userId],
    );
    res.json({ message: "Task updated" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update task" });
  }
});

// Delete a task
app.delete("/api/tasks/:id", auth, async (req, res) => {
  const taskId = req.params.id;
  try {
    const [result] = await pool.query(
      "DELETE FROM tasks WHERE id = ? AND user_id = ?",
      [taskId, req.userId],
    );
    if (result.affectedRows === 0)
      return res.status(404).json({ error: "Task not found" });
    res.json({ message: "Task deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete task" });
  }
});


// ---------- START SERVER ----------
const PORT = 5000;
app.listen(PORT, () => console.log(`🚀 Backend on port ${PORT}`));

const express = require("express");
const mysql = require("mysql2/promise"); // or  something similar require;
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const port = 3000;

// Middleware to parse JSON bodies
app.use(express.json());
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// MySQL Connection Pool
const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "maguette",
  database: "facebook_backend",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Secret Key for JWT
const JWT_SECRET = "your_secret_key"; // Replace with a strong, secure key

// Middleware for JWT Authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Register Endpoint
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hashedPassword]
    );
    res.status(201).json({
      message: "User registered successfully",
      userId: result.insertId,
    });
  } catch (error) {
    res.status(500).json({ message: "Error registering user", error });
  }
});

// Login Endpoint
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }

  try {
    const [rows] = await pool.query("SELECT * FROM users WHERE username = ?", [
      username,
    ]);
    const user = rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ message: "Error logging in", error });
  }
});

// Get User by ID (Protected Endpoint)
app.get("/users/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [rows] = await pool.query(
      "SELECT id, username FROM users WHERE id = ?",
      [id]
    );
    const user = rows[0];

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Error fetching user", error });
  }
});

// Get Posts (Query Parameters)
app.get("/posts", async (req, res) => {
  const { userId } = req.query;

  try {
    const [rows] = await pool.query("SELECT * FROM posts WHERE user_id = ?", [
      userId,
    ]);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: "Error fetching posts", error });
  }
});

// Get All Posts (Public Endpoint)
app.get("/posts/all", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM posts");
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: "Error fetching all posts", error });
  }
});

// Create Post (Protected, User-Specific)
app.post("/posts", authenticateToken, async (req, res) => {
  const { title, content } = req.body;
  const userId = req.user.userId;

  if (!title || !content) {
    return res.status(400).json({ message: "Title and content are required" });
  }

  try {
    const [result] = await pool.query(
      "INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)",
      [userId, title, content]
    );
    res
      .status(201)
      .json({ message: "Post created successfully", postId: result.insertId });
  } catch (error) {
    res.status(500).json({ message: "Error creating post", error });
  }
});

// Edit Post (Protected, User-Specific)
app.put("/posts/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { title, content } = req.body;
  const userId = req.user.userId;

  if (!title || !content) {
    return res.status(400).json({ message: "Title and content are required" });
  }

  try {
    const [result] = await pool.query(
      "UPDATE posts SET title = ?, content = ? WHERE id = ? AND user_id = ?",
      [title, content, id, userId]
    );

    if (result.affectedRows === 0) {
      return res
        .status(404)
        .json({ message: "Post not found or not authorized" });
    }

    res.json({ message: "Post updated successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error updating post", error });
  }
});

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});

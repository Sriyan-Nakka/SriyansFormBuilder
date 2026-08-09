require("dotenv").config();

const path = require("path");
const bcrypt = require("bcrypt");
const express = require("express");
const { createClient } = require("@libsql/client");

const app = express();

const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

app.use(express.json());
app.use(express.static("public"));

app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "public/auth", "signup.html"));
});

app.get("/signup/success", (req, res) => {
  res.sendFile(path.join(__dirname, "public/auth", "signupComplete.html"));
});

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.execute({
      sql: "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
      args: [username, email, hashedPassword],
    });

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public/auth", "login.html"));
});

app.get("/api/auth/login/username", async (req, res) => {
  try {
    const { username, password } = req.query;

    const result = await db.execute({
      sql: "SELECT * FROM login WHERE username = ?",
      args: [username],
    });

    const user = result.rows[0];

    if (!user) {
      return res.json({
        success: false,
        message: "User not found",
      });
    }

    const match = await bcrypt.compare(password, user.password);

    if (match) {
      res.json({
        success: true,
        message: "Login successful",
      });
    } else {
      res.json({
        success: false,
        message: "Incorrect password",
      });
    }
  } catch (err) {
    console.error(err);

    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

app.get("/api/auth/login/email", async (req, res) => {
  try {
    const { email, password } = req.query;

    const result = await db.execute({
      sql: "SELECT * FROM login WHERE username = ?",
      args: [email],
    });

    const user = result.rows[0];

    if (!user) {
      return res.json({
        success: false,
        message: "User not found",
      });
    }

    const match = await bcrypt.compare(password, user.password);

    if (match) {
      res.json({
        success: true,
        message: "Login successful",
      });
    } else {
      res.json({
        success: false,
        message: "Incorrect password",
      });
    }
  } catch (err) {
    console.error(err);

    res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log("Server running on 3001");
});

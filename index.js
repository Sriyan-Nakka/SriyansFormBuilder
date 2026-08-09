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

async function generateUniqueUsername({ accName, username }) {
  let baseUsername = (username?.trim() || "").trim();

  if (!baseUsername) {
    baseUsername = accName
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "");
  }

  let candidate = baseUsername;

  while (true) {
    const check = await db.execute({
      sql: "SELECT username FROM users WHERE username = ?",
      args: [candidate],
    });

    if (check.rows.length === 0) return candidate;

    const digits = Array.from({ length: 3 }, () =>
      Math.floor(Math.random() * 10),
    ).join("");
    candidate = `${baseUsername.split("-")[0]}-${digits}`;
  }
}

app.post("/api/auth/signup/check-username", async (req, res) => {
  try {
    const { accName, username } = req.body;

    const suggested = await generateUniqueUsername({ accName, username });

    res.json({ success: true, username: suggested });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Username check failed" });
  }
});

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { accName, username, password } = req.body;

    const finalUsername = await generateUniqueUsername({ accName, username });
    const hashedPassword = await bcrypt.hash(password, 10);

    await db.execute({
      sql: `
        INSERT INTO users (accName, username, password)
        VALUES (?, ?, ?)
      `,
      args: [accName, finalUsername, hashedPassword],
    });

    res.json({ success: true, username: finalUsername });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: err });
  }
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public/auth", "login.html"));
});

app.get("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.query;

    const result = await db.execute({
      sql: "SELECT * FROM users WHERE username = ?",
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

    if (!match) {
      return res.json({
        success: false,
        message: "Incorrect password",
      });
    }

    req.session.user = {
      id: user.id,
      username: user.username,
    };

    res.json({
      success: true,
      message: "Login successful",
    });
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

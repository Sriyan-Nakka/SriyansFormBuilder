require("dotenv").config();

const path = require("path");
const bcrypt = require("bcrypt");
const express = require("express");
const { createClient } = require("@libsql/client");
const session = require("express-session");

const app = express();

const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

app.use(express.json());
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 30,
    },
  }),
);

app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "public/auth", "signup.html"));
});

app.get("/signup/success", (req, res) => {
  res.sendFile(path.join(__dirname, "public/auth", "signupComplete.html"));
});

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { accName, username, password } = req.body;

    // Generate base username if none was provided
    let finalUsername = username?.trim();

    if (!finalUsername) {
      finalUsername = accName
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "");
    }

    // Check if username already exists
    const existing = await db.execute({
      sql: "SELECT username FROM users WHERE username = ?",
      args: [finalUsername],
    });

    // If taken, keep generating 3 random letters
    while (existing.rows.length > 0) {
      const letters = Array.from({ length: 3 }, () => {
        const letter = String.fromCharCode(65 + Math.floor(Math.random() * 26));

        return Math.random() < 0.5
          ? letter.toUpperCase()
          : letter.toLowerCase();
      }).join("");

      finalUsername = `${finalUsername.split("-")[0]}-${letters}`;

      const check = await db.execute({
        sql: "SELECT username FROM users WHERE username = ?",
        args: [finalUsername],
      });

      if (check.rows.length === 0) break;
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.execute({
      sql: `
        INSERT INTO users (accName, username, password)
        VALUES (?, ?, ?)
      `,
      args: [accName, finalUsername, hashedPassword],
    });

    req.session.user = {
      username: finalUsername,
    };

    res.json({
      success: true,
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      success: false,
      message: "Signup failed",
    });
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

app.get("/api/auth/me", (req, res) => {
  if (!req.session.user) {
    return res.json({ loggedIn: false });
  }

  res.json({
    loggedIn: true,
    user: req.session.user,
  });
});

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log("Server running on 3001");
});

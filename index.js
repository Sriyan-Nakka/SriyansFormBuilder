require("dotenv").config();

const path = require("path");
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
  res.sendFile(path.join(__dirname, "public", "signup.html"));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log("Server running on 3001");
});

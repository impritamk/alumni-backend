import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { pool } from "./db.js";
import dotenv from "dotenv";

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

// -------- REGISTER --------
app.post("/auth/register", async (req, res) => {
  const { email, password, first_name, last_name } = req.body;

  try {
    const hashed = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (email, password, first_name, last_name)
       VALUES ($1, $2, $3, $4)
       RETURNING id, email`,
      [email, hashed, first_name, last_name]
    );

    res.json({ message: "Registered", user: result.rows[0] });
  } catch (e) {
    res.status(400).json({ error: "Email already exists" });
  }
});

// -------- LOGIN --------
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

  if (result.rows.length === 0)
    return res.status(400).json({ error: "Invalid email" });

  const user = result.rows[0];
  const match = await bcrypt.compare(password, user.password);

  if (!match) return res.status(400).json({ error: "Wrong password" });

  const token = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ message: "Login success", token, user });
});

// -------- DIRECTORY --------
app.get("/users/all", async (req, res) => {
  const data = await pool.query(
    "SELECT id, first_name, last_name, bio, skills, passout_year FROM users"
  );
  res.json(data.rows);
});

// -------- ROOT --------
app.get("/", (req, res) => {
  res.send("Backend working");
});

// -------- START SERVER --------
const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log("Server running on PORT", PORT);
});



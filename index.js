import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import dotenv from "dotenv";
dotenv.config();

const app = express();
const port = 3030;

const saltRounds = 10;

const users = [];

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

async function generatePassword(plainPassword) {
  const salt = bcrypt.genSaltSync(saltRounds);
  return bcrypt.hashSync(plainPassword, salt);
}

async function comparePassword(plainPassword, hashedPassword) {
  return await bcrypt.compare(plainPassword, hashedPassword);
}

app.post("/register", async function (req, res) {
  const { username, password } = req.body;
  const existingUser = users.find((user) => user.username == username);

  if (existingUser)
    return res.status(409).json({ message: "User already registered" });

  const hashedPassword = await generatePassword(password);

  users.push({ username, password: hashedPassword });

  res.status(201).json({
    message: "User registered successfully!",
    user: { username: username },
  });
});

app.post("/login", async function (req, res) {
  const { username, password } = req.body;

  const user = users.find((user) => user.username == username);

  if (!user) return res.status(404).json({ message: "User not found" });

  const isMatch = await comparePassword(password, user.password);

  if (!isMatch) return res.status(401).json({ message: "Wrong password" });

  const acessToken = jwt.sign(
    { username: user.username },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "60s" }
  );

  return res.status(200).json({ acessToken: acessToken });
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, function (err, user) {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.get("/protected", authenticateToken, function (req, res) {
  return res
    .status(200)
    .json({ message: `Access allowed for user ${req.user.username}!` });
});

app.listen(port, function () {
  console.log(`Listening on port ${port}`);
});

export { generatePassword, comparePassword };

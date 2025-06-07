import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import dotenv from "dotenv";
dotenv.config();

const saltRounds = 10;

const app = express();
const port = 3030;

const users = [];

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

async function generatePassword(plainPassword) {
  const salt = bcrypt.genSaltSync(saltRounds);
  return bcrypt.hashSync(plainPassword, salt);
}

async function comparePassword(plainPassword) {
  bcrypt.compare(plainPassword, password).then((res) => {
    return res;
  });
}

app.post("/register", async function (req, res) {
  const { nome, senha } = req.body;
  const password = await generatePassword(senha);
  // comparePassword(req.body.senha);

  users.push({ nome, password });

  res.status(201).json(users);
});

app.post("/login", async function (req, res) {
  const { nome, senha } = req.body;

  const user = users.find((user) => user.nome == nome);

  if (!user) {
    res.status(404).json({ message: "no user" });
  }

  const passwordMatch = await bcrypt.compare(senha, user.password);

  if (passwordMatch) {
    const acessToken = jwt.sign(
      { username: user.nome },
      process.env.ACCESS_TOKEN_SECRET
    );
    res.status(200).json({ acessToken: acessToken });
    return;
  } else {
    res.status(200).json({ message: "password doesnt match" });
    return;
  }
});

app.get("/protected", function (req, res) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, function (err, user) {
    if (err) return res.sendStatus(401);
  });

  return res.status(200).json({ message: "Ok" });
});

app.listen(port, function () {
  console.log(`Listening on port ${port}`);
});

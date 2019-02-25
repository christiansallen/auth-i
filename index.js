const express = require("express");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");

const db = require("./database/dbConfig.js");
const Users = require("./users/users-module.js");

const server = express();

server.use(helmet());
server.use(express.json());

const port = 5000;
server.listen(port, () => {
  console.log(`Server is running on port number ${port}!`);
});

// ----------------------- ENDPOINTS ----------------------

server.post("/api/register", (req, res) => {
  let { username, password } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  password = hash;

  Users.add({ username, password })
    .then(user => {
      res.status(201).json(user);
    })
    .catch(() => res.status(500).json({ message: "Server error" }));
});

server.post("/api/login", (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: "Logged In!" });
      } else {
        res.status(401).json({ message: "You shall not pass!" });
      }
    })
    .catch(() => res.status(500).json({ message: "Server error" }));
});

const restricted = (req, res, next) => {
  const { username, password } = req.headers;

  if (username && password) {
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          next();
        } else {
          res.status(401).json({ message: "You shall not pass!" });
        }
      })
      .catch(() => res.status(500).json({ message: "Error in middleware" }));
  } else {
    res.status(401).json({ message: "No credentials given" });
  }
};

server.get("/api/users", restricted, (req, res) => {
  Users.find()
    .then(user => {
      res.status(200).json(user);
    })
    .catch(() => res.status(500).json({ message: "Server error" }));
});

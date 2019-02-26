const express = require("express");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const KnexSessionStore = require("connect-session-knex")(session);

const db = require("./database/dbConfig.js");
const Users = require("./users/users-model.js");

const server = express();

const sessionConfig = {
  name: "cookies!",
  secret: "this is my secret",
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
    secure: false
  },
  httpOnly: true,
  reSave: false,
  saveUninitialized: false,

  store: new KnexSessionStore({
    knex: db,
    tablename: "sessions",
    sidfieldname: "sid",
    createtable: true,
    clearInterval: 1000 * 60 * 60 * 24
  })
};

server.use(helmet());
server.use(express.json());
server.use(session(sessionConfig));

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

  Users.findBy({ username: username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = user;
        res.status(200).json({ message: "Logged In! + a cookie!" });
      } else {
        res.status(401).json({ message: "You shall not pass!" });
      }
    })
    .catch(() => res.status(500).json({ message: "Server error" }));
});

const restricted = (req, res, next) => {
  if (req.session && req.session.user) {
    next();
  } else {
    res.status(401).json({ message: "You shall not pass!" });
  }
};

// const restricted = (req, res, next) => {
//   const { username, password } = req.headers;

//   if (username && password) {
//     Users.findBy({ username })
//       .first()
//       .then(user => {
//         if (user && bcrypt.compareSync(password, user.password)) {
//           next();
//         } else {
//           res.status(401).json({ message: "You shall not pass!" });
//         }
//       })
//       .catch(() => res.status(500).json({ message: "Error in middleware" }));
//   } else {
//     res.status(401).json({ message: "No credentials given" });
//   }
// };

server.get("/api/users", restricted, (req, res) => {
  Users.find()
    .then(user => {
      res.status(200).json(user);
    })
    .catch(() => res.status(500).json({ message: "Server error" }));
});

server.get("/api/logout", (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res.status(400).json({ message: "Session destroy error" });
      } else {
        res.status(200).json({ message: "BYE! You are now logged out!" });
      }
    });
  } else {
    res.end();
  }
});

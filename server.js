const express = require("express");
const app = express();

const server = require("http").createServer(app);

const io = require("socket.io")(server);

const jwt = require("jsonwebtoken");

const sqlite3 = require("sqlite3").verbose();

const path = require("path");

/* =========================
   CONFIG
========================= */

const CHAVE = "SUPER_CHAVE_SECRETA";

/* =========================
   DATABASE
========================= */

const db = new sqlite3.Database("./database.db");

/* =========================
   TABELAS
========================= */

db.serialize(() => {

  // usuários

  db.run(`
    
    CREATE TABLE IF NOT EXISTS usuarios (

      id INTEGER PRIMARY KEY AUTOINCREMENT,

      usuario TEXT UNIQUE,

      senha TEXT,

      validade TEXT

    )

  `);

});

/* =========================
   PRIMEIRO USUÁRIO
========================= */

db.get(
  "SELECT * FROM usuarios WHERE usuario = ?",
  ["admin"],
  (err, row) => {

    if (!row) {

      // validade inicial
      // exemplo: 30 dias

      const validade = new Date();

      validade.setDate(validade.getDate() + 30);

      db.run(
        `
        INSERT INTO usuarios
        (usuario, senha, validade)
        VALUES (?, ?, ?)
        `,
        [
          "admin",
          "123456",
          validade.toISOString()
        ]
      );

      console.log("Usuário inicial criado");

    }

  }
);

/* =========================
   MIDDLEWARES
========================= */

app.use(express.json());

app.use(express.static(__dirname));

/* =========================
   LOGIN
========================= */

app.post("/login", (req, res) => {

  const { usuario, senha } = req.body;

  db.get(
    `
    SELECT * FROM usuarios
    WHERE usuario = ?
    `,
    [usuario],
    (err, user) => {

      if (!user) {

        return res.status(401).json({
          erro: "Usuário não encontrado"
        });

      }

      if (user.senha !== senha) {

        return res.status(401).json({
          erro: "Senha inválida"
        });

      }

      // verifica validade

      const agora = new Date();

      const validade = new Date(user.validade);

      // licença vencida

      if (agora > validade) {

        return res.status(403).json({
          licenca: false,
          erro: "Licença vencida"
        });

      }

      // gera token

      const token = jwt.sign(
        {
          id: user.id,
          usuario: user.usuario
        },
        CHAVE,
        {
          expiresIn: "1h"
        }
      );

      res.json({
        token,
        validade: user.validade
      });

    }
  );

});

/* =========================
   VALIDAR TOKEN
========================= */

function autenticar(req, res, next) {

  const auth = req.headers.authorization;

  if (!auth) {

    return res.status(401).json({
      erro: "Token ausente"
    });

  }

  const token = auth.split(" ")[1];

  jwt.verify(token, CHAVE, (err, decoded) => {

    if (err) {

      return res.status(403).json({
        erro: "Token inválido"
      });

    }

    req.usuario = decoded;

    next();

  });

}

app.get("/validar-token", autenticar, (req, res) => {

  res.json({
    ok: true
  });

});

/* =========================
   RENOVAR LICENÇA
========================= */

app.post("/renovar", (req, res) => {

  const { usuario, chave } = req.body;

  // chave secreta da licença

  if (chave !== "LICENCA-2026") {

    return res.status(401).json({
      erro: "Licença inválida"
    });

  }

  // adiciona +30 dias

  const novaData = new Date();

  novaData.setDate(novaData.getDate() + 30);

  db.run(
    `
    UPDATE usuarios
    SET validade = ?
    WHERE usuario = ?
    `,
    [
      novaData.toISOString(),
      usuario
    ],
    function(err) {

      if (err) {

        return res.status(500).json({
          erro: "Erro ao renovar"
        });

      }

      res.json({
        ok: true,
        validade: novaData
      });

    }
  );

});

/* =========================
   SOCKET
========================= */

let alertas = [];

io.on("connection", (socket) => {

  socket.emit("listaAlertas", alertas);

  socket.on("novoAlerta", (dados) => {

    const alerta = {

      id: Date.now(),

      linha: dados.linha,

      status: "PENDENTE",

      hora: new Date().toLocaleTimeString()

    };

    alertas.push(alerta);

    if (alertas.length > 50) {

      alertas.shift();

    }

    io.emit("listaAlertas", alertas);

  });

  socket.on("coletar", (id) => {

    alertas = alertas.map(a => {

      if (a.id === id) {

        a.status = "ACAMINHO";

      }

      return a;

    });

    io.emit("listaAlertas", alertas);

  });

  socket.on("finalizar", (id) => {

    alertas = alertas.map(a => {

      if (a.id === id) {

        a.status = "FINALIZADO";

      }

      return a;

    });

    io.emit("listaAlertas", alertas);

  });

});

/* =========================
   START
========================= */

server.listen(3000, () => {

  console.log("Servidor ON");

});
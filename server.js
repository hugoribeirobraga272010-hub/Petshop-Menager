
require("dotenv").config();

const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const path = require("path");

const app = express();

app.set("trust proxy", 1);

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());

// Configuração SSL Aiven
if (!process.env.DB_SSL_CA) {
    throw new Error("Certificado DB_SSL_CA não encontrado no .env");
}

const ssl = {
    ca: process.env.DB_SSL_CA.replace(/\\n/g, "\n"),
    rejectUnauthorized: true
};

// Conexão com o banco
const db = mysql.createPool({
    host: process.env.HOST,
    port: Number(process.env.PORT || 3306),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: ssl,
    waitForConnections: true,
    connectionLimit: 5,
    queueLimit: 0
});

// Criar tabelas
async function criarBanco() {
    await db.execute(`
        CREATE TABLE IF NOT EXISTS atendimentos (
            id INT PRIMARY KEY AUTO_INCREMENT,
            tutor VARCHAR(100) NOT NULL,
            pet VARCHAR(100) NOT NULL,
            especie ENUM('Cachorro', 'Gato', 'Outro') NOT NULL,
            servico VARCHAR(100) NOT NULL,
            valor DECIMAL(10,2) NOT NULL,
            data_atendimento DATE NOT NULL,
            criacao_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB
    `);

    await db.execute(`
        CREATE TABLE IF NOT EXISTS usuario (
            id INT PRIMARY KEY AUTO_INCREMENT,
            senha VARCHAR(255) NOT NULL,
            email VARCHAR(70) NOT NULL UNIQUE
        ) ENGINE=InnoDB
    `);

    await iniciar();
}

// Criar administrador
async function iniciar() {
    try {
        const [usuario] = await db.execute(
            "SELECT id FROM usuario WHERE email = ?",
            [process.env.ADMIN_EMAIL]
        );

        if (usuario.length === 0) {
            const senhaHash = await bcrypt.hash(
                process.env.ADMIN_SENHA,
                10
            );

            await db.execute(
                "INSERT INTO usuario (email, senha) VALUES (?, ?)",
                [process.env.ADMIN_EMAIL, senhaHash]
            );

            console.log("Admin criado");
        }

    } catch (erro) {
        console.log("Erro ao criar administrador:", erro);
        throw erro;
    }
}

// Salvar atendimento
app.post("/api/atendimento", async (req, res) => {
    try {
        const { tutor, pet, especie, servico, valor, data } = req.body;

        if (
            !tutor ||
            !pet ||
            !especie ||
            !servico ||
            valor === undefined ||
            valor === null ||
            !data
        ) {
            return res.status(400).json({
                erro: "Confira todos os campos"
            });
        }

        if (
            typeof tutor !== "string" ||
            typeof pet !== "string" ||
            typeof servico !== "string"
        ) {
            return res.status(400).json({
                erro: "Dados inválidos"
            });
        }

        if (
            !Number.isFinite(Number(valor)) ||
            Number(valor) <= 0
        ) {
            return res.status(400).json({
                erro: "Valor deve ser maior que 0."
            });
        }

        if (!["Cachorro", "Gato", "Outro"].includes(especie)) {
            return res.status(400).json({
                erro: "Espécie inválida."
            });
        }

        const [resultado] = await db.execute(
            `INSERT INTO atendimentos
            (tutor, pet, especie, servico, valor, data_atendimento)
            VALUES (?, ?, ?, ?, ?, ?)`,
            [
                tutor.trim(),
                pet.trim(),
                especie,
                servico.trim(),
                Number(valor),
                data
            ]
        );

        res.status(201).json({
            mensagem: "Atendimento salvo!",
            id: resultado.insertId
        });

    } catch (erro) {
        console.log(erro);

        res.status(500).json({
            erro: "Erro de conexão com o banco"
        });
    }
});

// Login
app.post("/api/login", async (req, res) => {
    try {
        const { email, senha } = req.body;

        if (!email || !senha) {
            return res.status(400).json({
                erro: "Informe e-mail e senha!"
            });
        }

        const [usuario] = await db.execute(
            "SELECT id, email, senha FROM usuario WHERE email = ?",
            [email.trim()]
        );

        if (usuario.length === 0) {
            return res.status(401).json({
                erro: "Credenciais incorretas."
            });
        }

        const dados = usuario[0];

        const senhaCorreta = await bcrypt.compare(
            senha,
            dados.senha
        );

        if (!senhaCorreta) {
            return res.status(401).json({
                erro: "Credenciais inválidas"
            });
        }

        const token = jwt.sign(
            {
                id: dados.id,
                email: dados.email
            },
            process.env.JWT_SEGREDO,
            {
                expiresIn: "1h"
            }
        );

        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 60 * 60 * 1000
        });

        res.json({
            mensagem: "Login realizado"
        });

    } catch (erro) {
        console.log(erro);

        res.status(500).json({
            erro: "Erro de conexão com o banco de dados."
        });
    }
});

// Autenticação
function autenticar(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        if (req.path.startsWith("/api/")) {
            return res.status(401).json({
                erro: "Você precisa fazer login para acessar esta página."
            });
        }

        return res.redirect("/login.html");
    }

    try {
        req.usuario = jwt.verify(
            token,
            process.env.JWT_SEGREDO
        );

        next();

    } catch (erro) {
        res.clearCookie("token", {
            httpOnly: true,
            sameSite: "strict",
            secure: process.env.NODE_ENV === "production"
        });

        if (req.path.startsWith("/api/")) {
            return res.status(401).json({
                erro: "Sessão inválida ou expirada."
            });
        }

        return res.redirect("/login.html");
    }
}

// Dashboard protegido
app.get("/dashboard", autenticar, (req, res) => {
    res.sendFile(
        path.join(__dirname, "private", "dashboard.html")
    );
});

// Logout
app.post("/api/logout", (req, res) => {
    res.clearCookie("token", {
        httpOnly: true,
        sameSite: "strict",
        secure: process.env.NODE_ENV === "production"
    });

    res.json({
        mensagem: "Logout efetuado"
    });
});

// Verificar login
app.get("/api/verificar", autenticar, (req, res) => {
    res.json({
        autenticado: true,
        usuario: req.usuario
    });
});

// Conectar com Python
async function conectarPython(endpoint, atendimentos, res, tipo) {
    try {
        const url = process.env.PYTHON_API_URL || "http://127.0.0.1:5001";

        const resposta = await fetch(
            `${url.replace(/\/+$/, "")}${endpoint}`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ atendimentos })
            }
        );

        if (!resposta.ok) {
            throw new Error(`Erro do Python: ${resposta.status}`);
        }

        const arquivo = Buffer.from(
            await resposta.arrayBuffer()
        );

        if (tipo === "pdf") {
            res.setHeader("Content-Type", "application/pdf");

            res.setHeader(
                "Content-Disposition",
                "attachment; filename=relatorio-petshop.pdf"
            );

        } else {
            res.setHeader("Content-Type", "image/png");

            res.setHeader(
                "Content-Disposition",
                "inline; filename=graficos.png"
            );
        }

        res.send(arquivo);

    } catch (erro) {
        console.log(erro);

        if (!res.headersSent) {
            res.status(502).json({
                erro: "Não foi possível conectar com o servidor Python"
            });
        }
    }
}

// Gráficos
app.get("/api/graficos", autenticar, async (req, res) => {
    try {
        const [atendimentos] = await db.execute(`
            SELECT tutor, pet, especie, servico
            FROM atendimentos
        `);

        await conectarPython(
            "/graficos",
            atendimentos,
            res,
            "imagem"
        );

    } catch (erro) {
        console.log(erro);

        res.status(500).json({
            erro: "Erro ao buscar os atendimentos"
        });
    }
});

// PDF
app.get("/api/pdf", autenticar, async (req, res) => {
    try {
        const [atendimentos] = await db.execute(`
            SELECT tutor, pet, especie, servico
            FROM atendimentos
            ORDER BY criacao_em
        `);

        await conectarPython(
            "/pdf",
            atendimentos,
            res,
            "pdf"
        );

    } catch (erro) {
        console.log(erro);

        res.status(500).json({
            erro: "Erro ao buscar os atendimentos"
        });
    }
});

// Inicializar servidor
criarBanco()
    .then(() => {
        app.listen(3000, "0.0.0.0", () => {
            console.log("Servidor rodando na porta 3000");
        });
    })
    .catch((erro) => {
        console.log("Erro ao iniciar servidor:", erro);
        process.exit(1);
    });

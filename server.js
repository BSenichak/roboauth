import express from "express";
import { fileURLToPath } from "url";
import { dirname } from "path";
import { readFileSync } from "fs";
import jwt from "jsonwebtoken";
import bodyParser from "body-parser";
import db from "./database.js";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";

const SECRET_KEY = "ROBOCODE_PRIVET";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const index = readFileSync(`${__dirname}/static/index.html`).toString();
const login = readFileSync(`${__dirname}/static/login.html`).toString();
const register = readFileSync(`${__dirname}/static/register.html`).toString();
const style = readFileSync(`${__dirname}/static/style.css`).toString();

const app = express();


app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());


app.get("/", (req, res) => {
    res.send(index);
});

app.get("/login", (req, res) => {
    res.send(login);
});
app.get("/register", (req, res) => {
    res.send(register);
});

app.get("/style.css", (req, res) => {
    res.setHeader("Content-Type", "text/css");
    res.send(style);
});



app.post("/register", (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);

    db.run(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hashedPassword],
        function (err) {
            if (err) {
                return res
                    .status(500)
                    .send("There was a problem registering the user.");
            }

            const token = jwt.sign({ id: this.lastID }, SECRET_KEY, {
                expiresIn: 86400,
            }); // 24 hours
            res.status(200).send({ auth: true, token });
        }
    );
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        (err, user) => {
            if (err) {
                return res.status(500).send({ message: err });
            }
            if (!user) {
                return res.status(404).send({ message: "User not found." });
            }

            const passwordIsValid = bcrypt.compareSync(password, user.password);
            if (!passwordIsValid) {
                return res.status(401).send({ auth: false, token: null });
            }

            const token = jwt.sign({ id: user.id }, SECRET_KEY, {
                expiresIn: 60,
            });
            res.status(200).send({ auth: true, token });
        }
    );
});

app.get("/me", (req, res) => {
    const token = req.cookies["x-access-token"];
    if (!token) {
        return res
            .status(401)
            .send({ auth: false, message: "No token provided." });
    }

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res
                .status(500)
                .send({
                    auth: false,
                    message: "Failed to authenticate token.",
                });
        }

        db.get(
            "SELECT * FROM users WHERE id = ?",
            [decoded.id],
            (err, user) => {
                if (err) {
                    return res
                        .status(500)
                        .send({ message: "There was a problem finding the user." });
                }
                if (!user) {
                    return res.status(404).send({ message: "User not found." });
                }

                res.status(200).send(user);
            }
        );
    });
});

app.listen(3000);

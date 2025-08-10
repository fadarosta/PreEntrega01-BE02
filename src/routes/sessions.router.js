
import { Router } from "express";
import passport from "passport";
import jwt from "jsonwebtoken";
import initializePassport from "../config/passport.config.js";

initializePassport();
const router = Router();

const JWT_SECRET = process.env.JWT_SECRET || "changeme_jwt_secret";
const JWT_EXPIRES = process.env.JWT_EXPIRES || "1h";

function generateToken(user) {
    const payload = {
        id: user._id,
        email: user.email,
        role: user.role,
    };
    return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

router.post("/register", (req, res, next) => {
    passport.authenticate("register", { session: false }, (err, user, info) => {
        if (err) return next(err);
        if (!user) {
            return res.status(400).json({ status: "error", message: info?.message || "Error en registro" });
        }
        return res.status(201).json({
            status: "success", message: "Usuario registrado", user: {
                first_name: user.first_name, email: user.email, role: user.role
            }
        });
    })(req, res, next);
});

router.post("/login", (req, res, next) => {
    passport.authenticate("login", { session: false }, (err, user, info) => {
        if (err) return next(err);
        if (!user) {
            return res.status(401).json({ status: "error", message: info?.message || "Credenciales inválidas" });
        }

        const token = generateToken(user);
        const safeUser = {
            id: user._id,
            first_name: user.first_name,
            last_name: user.last_name,
            email: user.email,
            age: user.age,
            role: user.role,
        };
        return res.json({ status: "success", token, user: safeUser });
    })(req, res, next);
});

router.get("/current", passport.authenticate("current", { session: false }), (req, res) => {
    const user = req.user;
    const safeUser = {
        id: user._id,
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
        age: user.age,
        role: user.role,
    };
    res.json({ status: "success", user: safeUser });
});

export default router;

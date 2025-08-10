// src/config/passport.config.js
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import dotenv from "dotenv";
import { userModel } from "../dao/models/User.model.js";
import { createHash, isValidPassword } from "../utils/bcryptUtil.js";

dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET || "changeme_jwt_secret";

export default function initializePassport() {
    // REGISTRAR
    passport.use(
        "register",
        new LocalStrategy(
            { usernameField: "email", passReqToCallback: true },
            async (req, email, password, done) => {
                try {
                    const { first_name, last_name, age } = req.body;

                    // verificar existencia
                    const exists = await userModel.findOne({ email });
                    if (exists) {
                        return done(null, false, { message: "Usuario ya existente" });
                    }

                    // crear usuario y hashear contraseña
                    const newUser = await userModel.create({
                        first_name,
                        last_name,
                        email,
                        age,
                        password: createHash(password),
                    });

                    return done(null, newUser);
                } catch (err) {
                    return done(err);
                }
            }
        )
    );

    // LOGIN
    passport.use(
        "login",
        new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
            try {
                const user = await userModel.findOne({ email });
                if (!user) {
                    return done(null, false, { message: "Usuario no encontrado" });
                }

                // validar password
                if (!isValidPassword(user, password)) {
                    return done(null, false, { message: "Contraseña incorrecta" });
                }

                return done(null, user);
            } catch (err) {
                return done(err);
            }
        })
    );

    // JWT 
    passport.use(
        "current",
        new JwtStrategy(
            {
                jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
                secretOrKey: JWT_SECRET,
            },
            async (jwt_payload, done) => {
                try {
                    const user = await userModel.findById(jwt_payload.id);
                    if (!user) {
                        return done(null, false, { message: "Token válido pero usuario no existe" });
                    }
                    return done(null, user);
                } catch (err) {
                    return done(err, false);
                }
            }
        )
    );
}

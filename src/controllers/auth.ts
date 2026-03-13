import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import Usuario from '../models/Usuario';
import { generateToken } from '../utils/jwt';

/**
 * POST /auth/login
 * Verifica credenciales y, si son correctas, genera y devuelve el JWT.
 */
export const login = async (req: Request, res: Response, next: NextFunction) => {
    const { email, password } = req.body;

    try {
        // Buscar usuario por email
        const usuario = await Usuario.findOne({ email });
        if (!usuario) {
            return res.status(401).json({ message: 'Credenciales incorrectas' });
        }

        // Comparar contraseña
        const isMatch = await bcrypt.compare(password, usuario.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Credenciales incorrectas' });
        }

        // Generar token JWT
        const token = generateToken(usuario.name, usuario.email, usuario.organizacion as mongoose.Types.ObjectId);

        return res.status(200).json({
            message: 'Login exitoso',
            token,
            usuario: {
                _id: usuario._id,
                name: usuario.name,
                email: usuario.email,
                organizacion: usuario.organizacion
            }
        });
    } catch (error) {
        return res.status(500).json({ error });
    }
};

/**
 * POST /auth/refresh
 * Genera un nuevo token basado en el token actual (debe ser válido).
 */
export const refreshToken = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const user = (req as any).user;
        if (!user) {
            return res.status(401).json({ message: 'No hay información de usuario en el token' });
        }

        // Generar un nuevo token
        const token = generateToken(user.name, user.email, user.organizacion);

        return res.status(200).json({
            message: 'Token refrescado',
            token
        });
    } catch (error) {
        return res.status(500).json({ error });
    }
};

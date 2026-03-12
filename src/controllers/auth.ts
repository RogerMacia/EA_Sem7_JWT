import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import Usuario from '../models/Usuario';
import { generateToken } from '../utils/jwt';

/**
 * POST /auth/register
 * Crea un usuario nuevo (con contraseña hasheada). NO genera token.
 */
export const register = async (req: Request, res: Response, next: NextFunction) => {
    const { name, email, password, organizacion } = req.body;

    try {
        // Verificar si el email ya existe
        const exists = await Usuario.findOne({ email });
        if (exists) {
            return res.status(409).json({ message: 'El email ya está registrado' });
        }

        // Hashear la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Crear usuario
        const usuario = new Usuario({
            _id: new mongoose.Types.ObjectId(),
            name,
            email,
            password: hashedPassword,
            organizacion
        });

        const saved = await usuario.save();

        return res.status(201).json({
            message: 'Usuario registrado correctamente',
            usuario: {
                _id: saved._id,
                name: saved.name,
                email: saved.email,
                organizacion: saved.organizacion
            }
        });
    } catch (error) {
        return res.status(500).json({ error });
    }
};

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

import express from 'express';
import { register, login } from '../controllers/auth';
import Joi from 'joi';
import { ValidateJoi } from '../middleware/Joi';

const router = express.Router();

// Schemas de validación para auth
const registerSchema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    organizacion: Joi.string()
        .regex(/^[0-9a-fA-F]{24}$/)
        .required()
});

const loginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

/**
 * @openapi
 * tags:
 *   - name: Auth
 *     description: Endpoints de autenticación
 *
 * /auth/register:
 *   post:
 *     summary: Registra un nuevo usuario (NO genera token)
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, email, password, organizacion]
 *             properties:
 *               name:
 *                 type: string
 *                 example: "Omar"
 *               email:
 *                 type: string
 *                 example: "omar@gmail.com"
 *               password:
 *                 type: string
 *                 example: "secret123"
 *               organizacion:
 *                 type: string
 *                 example: "65f1c2a1b2c3d4e5f6789013"
 *     responses:
 *       201:
 *         description: Usuario registrado
 *       409:
 *         description: Email ya registrado
 *       422:
 *         description: Validación fallida
 */
router.post('/register', ValidateJoi(registerSchema), register);

/**
 * @openapi
 * /auth/login:
 *   post:
 *     summary: Inicia sesión y devuelve el JWT
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email:
 *                 type: string
 *                 example: "omar@gmail.com"
 *               password:
 *                 type: string
 *                 example: "secret123"
 *     responses:
 *       200:
 *         description: Login exitoso, devuelve token
 *       401:
 *         description: Credenciales incorrectas
 */
router.post('/login', ValidateJoi(loginSchema), login);

export default router;

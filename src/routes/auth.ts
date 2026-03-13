import express from 'express';
import { login, refreshToken } from '../controllers/auth';
import Joi from 'joi';
import { ValidateJoi } from '../middleware/Joi';
import { authenticateToken } from '../middleware/auth';

const router = express.Router();

// Schemas de validación para auth
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

/**
 * @openapi
 * /auth/refresh:
 *   get:
 *     summary: Refresca el token JWT
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Token refrescado correctamente
 *       401:
 *         description: No autorizado (token faltante o inválido)
 */
router.get('/refresh', authenticateToken, refreshToken);

export default router;

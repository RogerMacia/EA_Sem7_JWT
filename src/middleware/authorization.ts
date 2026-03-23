import { Response, NextFunction } from "express";
import { AuthRequest } from "./authentication";

export const Authorize = (req: AuthRequest, res: Response, next: NextFunction) => {
    const user = req.user;
    if (user?.role === "user") {
        if (user?.id === req.params.usuarioId) { next(); }
        
        return res.status(403).json({ message: "User unauthorized" })
    }
    else if (user?.role === "admin") {
        next();
    }
};

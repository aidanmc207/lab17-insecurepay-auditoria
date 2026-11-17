import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from './auth.service';

/**
 * Adjunta el token JWT del usuario autenticado en la cabecera Authorization
 * de cada solicitud hacia la API. El backend lo usa como unica fuente de identidad
 * para validar la propiedad de cuentas y transacciones (remediacion IDOR).
 */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const token = inject(AuthService).currentUser()?.token;
  if (!token || !req.url.startsWith('http://localhost:8080/api')) {
    return next(req);
  }
  return next(req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }));
};

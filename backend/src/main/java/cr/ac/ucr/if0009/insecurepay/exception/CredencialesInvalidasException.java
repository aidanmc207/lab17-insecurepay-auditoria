package cr.ac.ucr.if0009.insecurepay.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Se lanza ante cualquier fallo de login (usuario inexistente o contrasena incorrecta)
 * con un mensaje generico, para no permitir la enumeracion de usuarios (HTTP 401).
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class CredencialesInvalidasException extends RuntimeException {
    public CredencialesInvalidasException() {
        super("Usuario o contrasena incorrectos.");
    }
}

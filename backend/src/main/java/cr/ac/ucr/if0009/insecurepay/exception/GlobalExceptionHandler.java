package cr.ac.ucr.if0009.insecurepay.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.net.URI;
import java.time.Instant;
import java.util.UUID;

/**
 * [REMEDIACION A05:2021 - Security Misconfiguration / CWE-209]
 * Manejador global que traduce toda excepcion a una respuesta RFC 7807 (ProblemDetail).
 * Nunca se devuelven trazas, nombres de clases ni sentencias SQL: el detalle tecnico
 * queda solo en el log del servidor, enlazado con un identificador de incidente.
 *
 * Al extender ResponseEntityExceptionHandler, las excepciones propias de Spring MVC
 * (404 de ruta, JSON mal formado, parametro faltante, etc.) tambien salen como ProblemDetail.
 */
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private static final String TIPO_BASE = "https://insecurepay.fi.cr/errores/";

    @ExceptionHandler(NoAutenticadoException.class)
    public ProblemDetail noAutenticado(NoAutenticadoException ex, HttpServletRequest req) {
        return problema(HttpStatus.UNAUTHORIZED, "no-autenticado", "No autenticado", ex.getMessage(), req);
    }

    @ExceptionHandler(CredencialesInvalidasException.class)
    public ProblemDetail credencialesInvalidas(CredencialesInvalidasException ex, HttpServletRequest req) {
        return problema(HttpStatus.UNAUTHORIZED, "credenciales-invalidas", "Credenciales invalidas", ex.getMessage(), req);
    }

    @ExceptionHandler(AccesoDenegadoException.class)
    public ProblemDetail accesoDenegado(AccesoDenegadoException ex, HttpServletRequest req) {
        log.warn("Acceso denegado a {} {}: {}", req.getMethod(), req.getRequestURI(), ex.getMessage());
        return problema(HttpStatus.FORBIDDEN, "acceso-denegado", "Acceso denegado", ex.getMessage(), req);
    }

    @ExceptionHandler(RecursoNoEncontradoException.class)
    public ProblemDetail noEncontrado(RecursoNoEncontradoException ex, HttpServletRequest req) {
        return problema(HttpStatus.NOT_FOUND, "recurso-no-encontrado", "Recurso no encontrado", ex.getMessage(), req);
    }

    /** Reglas de negocio (monto invalido, fondos insuficientes): mensajes redactados por nosotros. */
    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail solicitudInvalida(IllegalArgumentException ex, HttpServletRequest req) {
        return problema(HttpStatus.BAD_REQUEST, "solicitud-invalida", "Solicitud invalida", ex.getMessage(), req);
    }

    /** Errores de persistencia: jamas se exponen el SQL, el motor ni el esquema. */
    @ExceptionHandler(DataAccessException.class)
    public ProblemDetail errorDatos(DataAccessException ex, HttpServletRequest req) {
        return errorInterno(ex, req);
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail errorGenerico(Exception ex, HttpServletRequest req) {
        return errorInterno(ex, req);
    }

    private ProblemDetail errorInterno(Exception ex, HttpServletRequest req) {
        String incidente = UUID.randomUUID().toString();
        log.error("Incidente {} en {} {}", incidente, req.getMethod(), req.getRequestURI(), ex);
        ProblemDetail pd = problema(HttpStatus.INTERNAL_SERVER_ERROR, "error-interno", "Error interno",
                "Ocurrio un error inesperado. Contacte a soporte indicando el identificador del incidente.", req);
        pd.setProperty("incidente", incidente);
        return pd;
    }

    private ProblemDetail problema(HttpStatus status, String tipo, String titulo, String detalle,
                                   HttpServletRequest req) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(status, detalle);
        pd.setType(URI.create(TIPO_BASE + tipo));
        pd.setTitle(titulo);
        pd.setInstance(URI.create(req.getRequestURI()));
        pd.setProperty("timestamp", Instant.now().toString());
        return pd;
    }
}

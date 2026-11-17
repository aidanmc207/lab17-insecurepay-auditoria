package cr.ac.ucr.if0009.insecurepay.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Date;

@Component
public class JwtUtil {

    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

    /** HMAC-SHA256 requiere una clave de al menos 256 bits (32 bytes). */
    static final int LONGITUD_MINIMA_BYTES = 32;

    // [REMEDIACION A02:2021 - Cryptographic Failures (CWE-798 / CWE-321)]
    // El secreto ya no vive en el repositorio: se inyecta con la variable de entorno JWT_SECRET.
    @Value("${jwt.secret:}")
    private String secret;

    @Value("${jwt.expiration-ms}")
    private long expirationMs;

    private SecretKey signingKey;

    @PostConstruct
    void inicializarClave() {
        if (secret == null || secret.isBlank()) {
            byte[] aleatoria = new byte[64];
            new SecureRandom().nextBytes(aleatoria);
            signingKey = Keys.hmacShaKeyFor(aleatoria);
            log.warn("JWT_SECRET no definida: se genero una clave HMAC aleatoria efimera. "
                    + "Los tokens se invalidaran al reiniciar. Defina JWT_SECRET en produccion.");
            return;
        }
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < LONGITUD_MINIMA_BYTES) {
            throw new IllegalStateException(
                    "JWT_SECRET debe tener al menos 256 bits (32 bytes) para HMAC-SHA256.");
        }
        signingKey = Keys.hmacShaKeyFor(bytes);
    }

    public String generateToken(String username, String rol, Long usuarioId) {
        return Jwts.builder()
                .subject(username)
                .claim("rol", rol)
                .claim("usuarioId", usuarioId)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(signingKey, Jwts.SIG.HS256)
                .compact();
    }

    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Extrae el username (claim "sub") de un token cuya firma y expiracion son validas.
     * Lanza una excepcion de JJWT si el token fue alterado o expiro.
     */
    public String extraerUsername(String token) {
        return getClaims(token).getSubject();
    }

    public boolean validateToken(String token) {
        try {
            getClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

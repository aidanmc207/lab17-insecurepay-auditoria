package cr.ac.ucr.if0009.insecurepay.service;

import cr.ac.ucr.if0009.insecurepay.exception.NoAutenticadoException;
import cr.ac.ucr.if0009.insecurepay.model.CuentaBancaria;
import cr.ac.ucr.if0009.insecurepay.model.Rol;
import cr.ac.ucr.if0009.insecurepay.model.Usuario;
import cr.ac.ucr.if0009.insecurepay.repository.UsuarioRepository;
import cr.ac.ucr.if0009.insecurepay.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import org.springframework.stereotype.Service;

/**
 * [REMEDIACION A01:2021 - Broken Access Control / IDOR]
 * Resuelve la identidad verificada del solicitante a partir del token JWT firmado.
 * Ningun servicio debe confiar en identificadores de usuario enviados por el cliente
 * (path, query o body); la unica fuente de identidad es el claim "sub" del token.
 */
@Service
public class SesionService {

    private static final String PREFIJO_BEARER = "Bearer ";

    private final JwtUtil jwtUtil;
    private final UsuarioRepository usuarioRepository;

    public SesionService(JwtUtil jwtUtil, UsuarioRepository usuarioRepository) {
        this.jwtUtil = jwtUtil;
        this.usuarioRepository = usuarioRepository;
    }

    public Usuario obtenerUsuarioAutenticado(String authHeader) {
        String token = extraerToken(authHeader);
        String username;
        try {
            username = jwtUtil.extraerUsername(token);
        } catch (JwtException | IllegalArgumentException e) {
            throw new NoAutenticadoException("Token de acceso invalido o expirado.");
        }
        return usuarioRepository.findByUsername(username)
                .orElseThrow(() -> new NoAutenticadoException("Token de acceso invalido o expirado."));
    }

    /** ADMIN y AUDITOR tienen acceso de solo lectura a todas las cuentas. */
    public boolean esPrivilegiado(Usuario usuario) {
        return usuario.getRol() == Rol.ADMIN || usuario.getRol() == Rol.AUDITOR;
    }

    public boolean esPropietario(Usuario usuario, CuentaBancaria cuenta) {
        return cuenta.getUsuario().getId().equals(usuario.getId());
    }

    private String extraerToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith(PREFIJO_BEARER)) {
            return authHeader.substring(PREFIJO_BEARER.length());
        }
        throw new NoAutenticadoException("Cabecera de autorizacion ausente o invalida.");
    }
}

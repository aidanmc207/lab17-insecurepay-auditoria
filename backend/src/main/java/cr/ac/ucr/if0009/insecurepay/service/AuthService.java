package cr.ac.ucr.if0009.insecurepay.service;

import cr.ac.ucr.if0009.insecurepay.dto.LoginRequest;
import cr.ac.ucr.if0009.insecurepay.dto.LoginResponse;
import cr.ac.ucr.if0009.insecurepay.exception.CredencialesInvalidasException;
import cr.ac.ucr.if0009.insecurepay.model.Usuario;
import cr.ac.ucr.if0009.insecurepay.repository.UsuarioRepository;
import cr.ac.ucr.if0009.insecurepay.util.JwtUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    private final UsuarioRepository usuarioRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    /**
     * Hash BCrypt de referencia que se compara cuando el usuario no existe, para que el
     * tiempo de respuesta sea equivalente y no revele que usernames estan registrados.
     */
    private final String hashSenuelo;

    public AuthService(UsuarioRepository usuarioRepository, JwtUtil jwtUtil, PasswordEncoder passwordEncoder) {
        this.usuarioRepository = usuarioRepository;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
        this.hashSenuelo = passwordEncoder.encode("senuelo-anti-enumeracion");
    }

    // [REMEDIACION A07:2021 - Identification & Authentication Failures (CWE-256 / CWE-916)]
    // La validacion se hace exclusivamente con passwordEncoder.matches(claveEnviada, hashAlmacenado).
    // Usuario inexistente y contrasena incorrecta producen la misma respuesta (401 generico).
    public LoginResponse autenticar(LoginRequest request) {
        if (request == null || request.getUsername() == null || request.getPassword() == null) {
            throw new CredencialesInvalidasException();
        }

        Optional<Usuario> encontrado = usuarioRepository.findByUsername(request.getUsername());
        String hashAlmacenado = encontrado.map(Usuario::getPassword).orElse(hashSenuelo);

        boolean coincide = passwordEncoder.matches(request.getPassword(), hashAlmacenado);
        if (encontrado.isEmpty() || !coincide) {
            throw new CredencialesInvalidasException();
        }

        Usuario usuario = encontrado.get();
        String token = jwtUtil.generateToken(usuario.getUsername(), usuario.getRol().name(), usuario.getId());

        return new LoginResponse(
                token,
                usuario.getUsername(),
                usuario.getNombreCompleto(),
                usuario.getRol().name(),
                usuario.getId()
        );
    }
}

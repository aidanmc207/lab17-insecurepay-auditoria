package cr.ac.ucr.if0009.insecurepay.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * [REMEDIACION A02:2021 - Cryptographic Failures / A07:2021 - Authentication Failures]
 * Las contrasenas se almacenan como hashes BCrypt (sal aleatoria por usuario y costo
 * adaptativo), nunca en texto plano.
 */
@Configuration
public class SecurityConfig {

    /** Factor de trabajo: 2^12 iteraciones (el minimo exigido por el laboratorio es 10). */
    public static final int BCRYPT_STRENGTH = 12;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(BCRYPT_STRENGTH);
    }
}

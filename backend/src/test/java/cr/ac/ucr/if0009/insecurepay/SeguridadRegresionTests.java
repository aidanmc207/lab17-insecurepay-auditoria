package cr.ac.ucr.if0009.insecurepay;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import cr.ac.ucr.if0009.insecurepay.repository.UsuarioRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Pruebas de regresion de la auditoria forense: cada prueba reproduce la PoC de un
 * hallazgo y verifica que el control defensivo la bloquea.
 * Carlos Mora (usuario 3) es dueno de la cuenta 2; Maria Rojas (usuario 4) de la cuenta 3.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class SeguridadRegresionTests {

    private static final String CUENTA_CARLOS = "CR05015202001026458901";
    private static final String CUENTA_MARIA = "CR05015202001026458902";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper mapper;

    @Autowired
    private UsuarioRepository usuarioRepository;

    private String tokenCarlos;

    @BeforeEach
    void iniciarSesion() throws Exception {
        tokenCarlos = login("carlos_mora", "carlos123");
    }

    // ------------------------------------------------------------ HALLAZGO-01
    @Test
    @DisplayName("HALLAZGO-01: el payload ' OR 1=1 -- se trata como texto literal")
    void sqlInjectionNeutralizada() throws Exception {
        mvc.perform(get("/api/transacciones/buscar").param("termino", "' OR 1=1 --")
                        .header("Authorization", bearer(tokenCarlos)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));

        mvc.perform(get("/api/transacciones/buscar").param("termino", "Reembolso")
                        .header("Authorization", bearer(tokenCarlos)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)));
    }

    // ------------------------------------------------------------ HALLAZGO-02
    @Test
    @DisplayName("HALLAZGO-02: consultar cuenta y saldo ajenos devuelve 403")
    void idorEnCuentasBloqueado() throws Exception {
        mvc.perform(get("/api/cuentas/3").header("Authorization", bearer(tokenCarlos)))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/cuentas/3/saldo").header("Authorization", bearer(tokenCarlos)))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/cuentas/usuario/4").header("Authorization", bearer(tokenCarlos)))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/cuentas").header("Authorization", bearer(tokenCarlos)))
                .andExpect(status().isForbidden());

        mvc.perform(get("/api/cuentas/2/saldo").header("Authorization", bearer(tokenCarlos)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cuentaId").value(2));
    }

    @Test
    @DisplayName("HALLAZGO-02: sin token o con token alterado devuelve 401")
    void sinTokenNoAutenticado() throws Exception {
        mvc.perform(get("/api/cuentas/2")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/cuentas/2").header("Authorization", bearer(tokenCarlos + "x")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("HALLAZGO-02: transferir desde una cuenta ajena devuelve 403 y no mueve fondos")
    void idorEnTransferenciaBloqueado() throws Exception {
        mvc.perform(post("/api/transacciones/transferir")
                        .header("Authorization", bearer(tokenCarlos))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(transferencia(3, CUENTA_CARLOS, "100000", "Retiro no autorizado")))
                .andExpect(status().isForbidden());

        String tokenMaria = login("maria_rojas", "maria123");
        mvc.perform(get("/api/cuentas/3/saldo").header("Authorization", bearer(tokenMaria)))
                .andExpect(jsonPath("$.saldo").value(4850000.00));
    }

    @Test
    @DisplayName("HALLAZGO-02: el auditor puede consultar cuentas ajenas")
    void auditorConsultaCuentas() throws Exception {
        String tokenAuditor = login("auditor_seguridad", "auditor2026");
        mvc.perform(get("/api/cuentas/3").header("Authorization", bearer(tokenAuditor)))
                .andExpect(status().isOk());
    }

    // ------------------------------------------------------------ HALLAZGO-03
    @Test
    @DisplayName("HALLAZGO-03: el concepto con HTML se persiste codificado")
    void xssAlmacenadoCodificado() throws Exception {
        String payload = "Pago <img src=\"x\" onerror=\"alert(1)\">";
        mvc.perform(post("/api/transacciones/transferir")
                        .header("Authorization", bearer(tokenCarlos))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(transferencia(2, CUENTA_MARIA, "1000", payload)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.conceptoHtml")
                        .value("Pago &lt;img src=&quot;x&quot; onerror=&quot;alert(1)&quot;&gt;"))
                .andExpect(jsonPath("$.conceptoHtml", not(containsString("<img"))));
    }

    // ------------------------------------------------------------ HALLAZGO-04
    @Test
    @DisplayName("HALLAZGO-04: las contrasenas se almacenan como hashes BCrypt de costo >= 10")
    void contrasenasConBcrypt() {
        usuarioRepository.findAll().forEach(u -> {
            assertThat(u.getPassword()).matches("^\\$2[aby]\\$1[0-9]\\$.{53}$");
            assertThat(u.getPassword()).doesNotContain(u.getUsername().split("_")[0]);
        });
    }

    @Test
    @DisplayName("HALLAZGO-04: usuario inexistente y clave incorrecta responden igual (401)")
    void loginSinEnumeracion() throws Exception {
        String claveIncorrecta = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"carlos_mora\",\"password\":\"incorrecta\"}"))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        String usuarioInexistente = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"no_existe\",\"password\":\"x\"}"))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        assertThat(mapper.readTree(claveIncorrecta).get("detail"))
                .isEqualTo(mapper.readTree(usuarioInexistente).get("detail"));
    }

    // ------------------------------------------------------------ HALLAZGO-05
    @Test
    @DisplayName("HALLAZGO-05: los errores siguen RFC 7807 y no exponen trazas")
    void erroresSinTrazas() throws Exception {
        mvc.perform(get("/api/cuentas/999").header("Authorization", bearer(tokenCarlos)))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.title").exists())
                .andExpect(jsonPath("$.trace").doesNotExist())
                .andExpect(jsonPath("$.exception").doesNotExist());

        mvc.perform(post("/api/transacciones/transferir")
                        .header("Authorization", bearer(tokenCarlos))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{malformado"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(not(containsString("jackson"))))
                .andExpect(content().string(not(containsString("at cr.ac.ucr"))));
    }

    // ------------------------------------------------------------ utilidades
    private String login(String usuario, String clave) throws Exception {
        String json = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + usuario + "\",\"password\":\"" + clave + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode nodo = mapper.readTree(json);
        return nodo.get("token").asText();
    }

    private String transferencia(long origen, String destino, String monto, String concepto) throws Exception {
        return mapper.writeValueAsString(java.util.Map.of(
                "cuentaOrigenId", origen,
                "numeroCuentaDestino", destino,
                "monto", new java.math.BigDecimal(monto),
                "conceptoHtml", concepto));
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }
}

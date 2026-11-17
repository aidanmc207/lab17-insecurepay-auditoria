package cr.ac.ucr.if0009.insecurepay.controller;

import cr.ac.ucr.if0009.insecurepay.dto.CuentaDto;
import cr.ac.ucr.if0009.insecurepay.service.CuentaService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/cuentas")
public class CuentaController {

    private final CuentaService cuentaService;

    public CuentaController(CuentaService cuentaService) {
        this.cuentaService = cuentaService;
    }

    // [REMEDIACION A01:2021] Solo ADMIN / AUDITOR
    @GetMapping
    public ResponseEntity<List<CuentaDto>> listarTodas(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader) {
        return ResponseEntity.ok(cuentaService.listarTodas(authHeader));
    }

    // [REMEDIACION A01:2021 - IDOR] Valida propiedad contra la identidad del JWT
    @GetMapping("/{id}")
    public ResponseEntity<CuentaDto> obtenerPorId(
            @PathVariable Long id,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader) {
        return ResponseEntity.ok(cuentaService.obtenerCuentaSegura(id, authHeader));
    }

    // [REMEDIACION A01:2021 - IDOR] Consulta de saldo con validacion de propiedad
    @GetMapping("/{id}/saldo")
    public ResponseEntity<Map<String, Object>> obtenerSaldo(
            @PathVariable Long id,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader) {
        CuentaDto cuenta = cuentaService.obtenerCuentaSegura(id, authHeader);
        return ResponseEntity.ok(Map.of(
                "cuentaId", cuenta.getId(),
                "numeroCuenta", cuenta.getNumeroCuenta(),
                "saldo", cuenta.getSaldo(),
                "moneda", cuenta.getMoneda()
        ));
    }

    // [REMEDIACION A01:2021 - BOLA] Solo las cuentas del propio usuario
    @GetMapping("/usuario/{usuarioId}")
    public ResponseEntity<List<CuentaDto>> obtenerPorUsuario(
            @PathVariable Long usuarioId,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader) {
        return ResponseEntity.ok(cuentaService.obtenerPorUsuario(usuarioId, authHeader));
    }
}

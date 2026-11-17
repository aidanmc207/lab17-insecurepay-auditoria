package cr.ac.ucr.if0009.insecurepay.service;

import cr.ac.ucr.if0009.insecurepay.dto.CuentaDto;
import cr.ac.ucr.if0009.insecurepay.exception.AccesoDenegadoException;
import cr.ac.ucr.if0009.insecurepay.exception.RecursoNoEncontradoException;
import cr.ac.ucr.if0009.insecurepay.model.CuentaBancaria;
import cr.ac.ucr.if0009.insecurepay.model.Usuario;
import cr.ac.ucr.if0009.insecurepay.repository.CuentaRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class CuentaService {

    private final CuentaRepository cuentaRepository;
    private final SesionService sesionService;

    public CuentaService(CuentaRepository cuentaRepository, SesionService sesionService) {
        this.cuentaRepository = cuentaRepository;
        this.sesionService = sesionService;
    }

    // [REMEDIACION A01:2021 - Broken Access Control]
    // El listado global de cuentas queda restringido a ADMIN / AUDITOR.
    public List<CuentaDto> listarTodas(String authHeader) {
        Usuario usuario = sesionService.obtenerUsuarioAutenticado(authHeader);
        if (!sesionService.esPrivilegiado(usuario)) {
            throw new AccesoDenegadoException("Acceso no autorizado al listado global de cuentas.");
        }
        return cuentaRepository.findAll().stream()
                .map(this::convertirADto)
                .collect(Collectors.toList());
    }

    // [REMEDIACION A01:2021 - IDOR (CWE-639)]
    // Se valida que la cuenta pertenezca al usuario del token antes de exponerla.
    public CuentaDto obtenerCuentaSegura(Long cuentaId, String authHeader) {
        Usuario usuario = sesionService.obtenerUsuarioAutenticado(authHeader);

        CuentaBancaria cuenta = cuentaRepository.findById(cuentaId)
                .orElseThrow(() -> new RecursoNoEncontradoException("Cuenta bancaria no existe."));

        if (!sesionService.esPropietario(usuario, cuenta) && !sesionService.esPrivilegiado(usuario)) {
            throw new AccesoDenegadoException("Acceso no autorizado a cuenta ajena.");
        }
        return convertirADto(cuenta);
    }

    // [REMEDIACION A01:2021 - BOLA]
    // Un cliente solo puede listar sus propias cuentas aunque altere el usuarioId de la URL.
    public List<CuentaDto> obtenerPorUsuario(Long usuarioId, String authHeader) {
        Usuario usuario = sesionService.obtenerUsuarioAutenticado(authHeader);
        if (!usuario.getId().equals(usuarioId) && !sesionService.esPrivilegiado(usuario)) {
            throw new AccesoDenegadoException("Acceso no autorizado a cuentas de otro cliente.");
        }
        return cuentaRepository.findByUsuarioId(usuarioId).stream()
                .map(this::convertirADto)
                .collect(Collectors.toList());
    }

    private CuentaDto convertirADto(CuentaBancaria cuenta) {
        CuentaDto dto = new CuentaDto();
        dto.setId(cuenta.getId());
        dto.setUsuarioId(cuenta.getUsuario().getId());
        dto.setTitular(cuenta.getUsuario().getNombreCompleto());
        dto.setNumeroCuenta(cuenta.getNumeroCuenta());
        dto.setTipoCuenta(cuenta.getTipoCuenta().name());
        dto.setSaldo(cuenta.getSaldo());
        dto.setMoneda(cuenta.getMoneda());
        dto.setActiva(cuenta.getActiva());
        return dto;
    }
}

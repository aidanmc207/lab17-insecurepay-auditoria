package cr.ac.ucr.if0009.insecurepay.service;

import cr.ac.ucr.if0009.insecurepay.dto.TransaccionDto;
import cr.ac.ucr.if0009.insecurepay.dto.TransferenciaDto;
import cr.ac.ucr.if0009.insecurepay.exception.AccesoDenegadoException;
import cr.ac.ucr.if0009.insecurepay.exception.RecursoNoEncontradoException;
import cr.ac.ucr.if0009.insecurepay.model.CuentaBancaria;
import cr.ac.ucr.if0009.insecurepay.model.Transaccion;
import cr.ac.ucr.if0009.insecurepay.model.Usuario;
import cr.ac.ucr.if0009.insecurepay.repository.CuentaRepository;
import cr.ac.ucr.if0009.insecurepay.repository.TransaccionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class TransaccionService {

    private final TransaccionRepository transaccionRepository;
    private final CuentaRepository cuentaRepository;
    private final SesionService sesionService;

    public TransaccionService(TransaccionRepository transaccionRepository,
                              CuentaRepository cuentaRepository,
                              SesionService sesionService) {
        this.transaccionRepository = transaccionRepository;
        this.cuentaRepository = cuentaRepository;
        this.sesionService = sesionService;
    }

    // [REMEDIACION A01:2021] Un cliente solo ve movimientos donde participa alguna de sus cuentas
    public List<TransaccionDto> listarTodas(String authHeader) {
        Usuario usuario = sesionService.obtenerUsuarioAutenticado(authHeader);
        return filtrarVisibles(transaccionRepository.findAll().stream(), usuario);
    }

    public TransaccionDto obtenerPorId(Long id, String authHeader) {
        Usuario usuario = sesionService.obtenerUsuarioAutenticado(authHeader);
        Transaccion transaccion = transaccionRepository.findById(id)
                .orElseThrow(() -> new RecursoNoEncontradoException("Transaccion no existe."));
        if (!puedeVer(usuario, transaccion)) {
            throw new AccesoDenegadoException("Acceso no autorizado a transaccion ajena.");
        }
        return convertirADto(transaccion);
    }

    public List<TransaccionDto> obtenerPorCuenta(Long cuentaId, String authHeader) {
        Usuario usuario = sesionService.obtenerUsuarioAutenticado(authHeader);
        CuentaBancaria cuenta = cuentaRepository.findById(cuentaId)
                .orElseThrow(() -> new RecursoNoEncontradoException("Cuenta bancaria no existe."));
        if (!sesionService.esPropietario(usuario, cuenta) && !sesionService.esPrivilegiado(usuario)) {
            throw new AccesoDenegadoException("Acceso no autorizado a cuenta ajena.");
        }
        return transaccionRepository.findByCuentaOrigenIdOrCuentaDestinoIdOrderByFechaDesc(cuentaId, cuentaId).stream()
                .map(this::convertirADto)
                .collect(Collectors.toList());
    }

    // [REMEDIACION A03:2021 - SQL Injection (CWE-89)]
    // Se elimina la concatenacion en createNativeQuery y se delega en una consulta JPQL
    // parametrizada. El termino viaja como dato literal y no puede alterar la sentencia.
    // Ademas, los resultados se filtran por propiedad (defensa en profundidad contra IDOR).
    public List<TransaccionDto> buscarPorConcepto(String termino, String authHeader) {
        Usuario usuario = sesionService.obtenerUsuarioAutenticado(authHeader);
        if (termino == null || termino.trim().isEmpty()) {
            return List.of();
        }
        return filtrarVisibles(transaccionRepository.buscarPorTerminoSeguro(termino.trim()).stream(), usuario);
    }

    // [REMEDIACION A01:2021 - IDOR en Transferencias Bancarias (CWE-639)]
    // La cuenta de origen debe pertenecer al usuario del token. Ni siquiera ADMIN/AUDITOR
    // pueden debitar fondos de cuentas ajenas.
    @Transactional
    public TransaccionDto transferir(TransferenciaDto dto, String authHeader) {
        Usuario usuario = sesionService.obtenerUsuarioAutenticado(authHeader);

        if (dto.getMonto() == null || dto.getMonto().compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("El monto a transferir debe ser mayor a cero.");
        }
        if (dto.getCuentaOrigenId() == null) {
            throw new IllegalArgumentException("Debe indicar la cuenta de origen.");
        }

        CuentaBancaria cuentaOrigen = cuentaRepository.findById(dto.getCuentaOrigenId())
                .orElseThrow(() -> new RecursoNoEncontradoException("Cuenta de origen no existe."));

        // Validar que la cuenta de origen pertenece al usuario autenticado
        if (!sesionService.esPropietario(usuario, cuentaOrigen)) {
            throw new AccesoDenegadoException("Fraude detectado: no puede debitar fondos de cuentas ajenas.");
        }

        CuentaBancaria cuentaDestino = cuentaRepository.findByNumeroCuenta(dto.getNumeroCuentaDestino())
                .orElseThrow(() -> new RecursoNoEncontradoException("Cuenta de destino no existe."));

        if (cuentaOrigen.getId().equals(cuentaDestino.getId())) {
            throw new IllegalArgumentException("La cuenta de origen y destino no pueden ser la misma.");
        }
        if (cuentaOrigen.getSaldo().compareTo(dto.getMonto()) < 0) {
            throw new IllegalArgumentException("Fondos insuficientes en la cuenta de origen seleccionada.");
        }

        // Efectuar debito y credito
        cuentaOrigen.setSaldo(cuentaOrigen.getSaldo().subtract(dto.getMonto()));
        cuentaDestino.setSaldo(cuentaDestino.getSaldo().add(dto.getMonto()));
        cuentaRepository.save(cuentaOrigen);
        cuentaRepository.save(cuentaDestino);

        Transaccion transaccion = new Transaccion();
        transaccion.setCuentaOrigen(cuentaOrigen);
        transaccion.setCuentaDestino(cuentaDestino);
        transaccion.setMonto(dto.getMonto());
        transaccion.setConceptoHtml(sanitizarTexto(dto.getConceptoHtml()));
        transaccion.setEstado("COMPLETADA");

        Transaccion guardada = transaccionRepository.save(transaccion);
        return convertirADto(guardada);
    }

    // [REMEDIACION A03:2021 - Stored XSS (CWE-79) - Defensa en profundidad]
    // Codifica los caracteres con significado en HTML antes de persistir, de modo que
    // ningun cliente (web, movil, reportes) reciba marcado ejecutable desde la BD.
    // El '&' se reemplaza primero para no codificar dos veces las entidades generadas.
    static String sanitizarTexto(String entrada) {
        if (entrada == null) {
            return "";
        }
        return entrada
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }

    private List<TransaccionDto> filtrarVisibles(Stream<Transaccion> transacciones, Usuario usuario) {
        return transacciones
                .filter(t -> puedeVer(usuario, t))
                .map(this::convertirADto)
                .collect(Collectors.toList());
    }

    private boolean puedeVer(Usuario usuario, Transaccion t) {
        return sesionService.esPrivilegiado(usuario)
                || sesionService.esPropietario(usuario, t.getCuentaOrigen())
                || sesionService.esPropietario(usuario, t.getCuentaDestino());
    }

    private TransaccionDto convertirADto(Transaccion t) {
        TransaccionDto dto = new TransaccionDto();
        dto.setId(t.getId());
        dto.setCuentaOrigenId(t.getCuentaOrigen().getId());
        dto.setNumeroCuentaOrigen(t.getCuentaOrigen().getNumeroCuenta());
        dto.setTitularOrigen(t.getCuentaOrigen().getUsuario().getNombreCompleto());
        dto.setCuentaDestinoId(t.getCuentaDestino().getId());
        dto.setNumeroCuentaDestino(t.getCuentaDestino().getNumeroCuenta());
        dto.setTitularDestino(t.getCuentaDestino().getUsuario().getNombreCompleto());
        dto.setMonto(t.getMonto());
        dto.setConceptoHtml(t.getConceptoHtml());
        dto.setFecha(t.getFecha());
        dto.setEstado(t.getEstado());
        return dto;
    }
}

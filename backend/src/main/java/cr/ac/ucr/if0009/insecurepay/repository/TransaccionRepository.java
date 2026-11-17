package cr.ac.ucr.if0009.insecurepay.repository;

import cr.ac.ucr.if0009.insecurepay.model.Transaccion;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TransaccionRepository extends JpaRepository<Transaccion, Long> {
    List<Transaccion> findByCuentaOrigenIdOrCuentaDestinoIdOrderByFechaDesc(Long cuentaOrigenId, Long cuentaDestinoId);

    // [REMEDIACION A03:2021 - SQL Injection]
    // Consulta JPQL declarativa con parametro con nombre (:termino). Hibernate lo envia
    // al motor como parametro vinculado (PreparedStatement), nunca como parte del SQL.
    @Query("SELECT t FROM Transaccion t " +
           "WHERE LOWER(CAST(t.conceptoHtml AS String)) LIKE LOWER(CONCAT('%', :termino, '%')) " +
           "   OR LOWER(t.estado) LIKE LOWER(CONCAT('%', :termino, '%')) " +
           "ORDER BY t.fecha DESC")
    List<Transaccion> buscarPorTerminoSeguro(@Param("termino") String termino);
}

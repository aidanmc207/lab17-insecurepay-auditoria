-- ==============================================================================
-- Datos Iniciales de Prueba - InsecurePay Digital Banking Portal
-- Contrasenas almacenadas como hashes BCrypt ($2a$, factor de trabajo 12).
-- Ningun valor en texto plano se persiste en la base de datos.
-- ==============================================================================

INSERT INTO USUARIOS (username, password, nombre_completo, email, rol) VALUES
('admin', '$2a$12$Q28.EcKoIqkdez9fiv/mlO191R7VtliwOyV9PCtb9pMtQZvNHFDUa', 'Administrador General de Sistemas', 'admin@insecurepay.fi.cr', 'ADMIN'),
('auditor_seguridad', '$2a$12$x12743px0Bp8fHdWXAcesek2p0pgyOG./Gg4eXQE8fXJrI6zsAJBu', 'Lic. Esteban Solano Chaves', 'esolano@insecurepay.fi.cr', 'AUDITOR'),
('carlos_mora', '$2a$12$G3tR6CUiTr08OWS5iXFipOLtQJthh10um6OnLGp39Db5PNi8PTcYK', 'Carlos Mora Morales', 'cmora@correo.cr', 'CLIENTE'),
('maria_rojas', '$2a$12$CIJDczMzEj1vaxKui1hYgO5h6ybcLVNVVMrkn.ZeI25dp.SDE69sy', 'María Rojas Soto', 'mrojas@empresa.cr', 'CLIENTE'),
('juan_perez', '$2a$12$FJjaJZm0OY7POCqiBBLVXu5vKRBluqgfzT/s/O5PZ8Dl.g4NXwBLm', 'Juan Pérez Delgado', 'jperez@correo.cr', 'CLIENTE');

INSERT INTO CUENTAS_BANCARIAS (usuario_id, numero_cuenta, tipo_cuenta, saldo, moneda, activa) VALUES
(1, 'CR05015202001026458900', 'CORRIENTE', 50000000.00, 'CRC', TRUE),
(3, 'CR05015202001026458901', 'AHORROS', 250000.00, 'CRC', TRUE),
(4, 'CR05015202001026458902', 'CORRIENTE', 4850000.00, 'CRC', TRUE),
(5, 'CR05015202001026458903', 'AHORROS', 75000.00, 'CRC', TRUE);

INSERT INTO TRANSACCIONES (cuenta_origen_id, cuenta_destino_id, monto, concepto_html, fecha, estado) VALUES
(2, 3, 45000.00, 'Pago de servicios profesionales de programacion. Verificado', '2026-03-01 10:15:00', 'COMPLETADA'),
(3, 4, 120000.00, 'Cancelacion cuota de alquiler oficina central. Factura electronica #8849.', '2026-03-05 14:30:00', 'COMPLETADA'),
(3, 2, 15000.00, 'Reembolso almuerzo equipo de trabajo.', '2026-03-12 11:20:00', 'COMPLETADA'),
(4, 2, 35000.00, 'Aporte fondo solidario cooperativo. Transferencia inmediata SINPE Movil', '2026-03-20 09:45:00', 'COMPLETADA');


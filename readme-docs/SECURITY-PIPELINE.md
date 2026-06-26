# Pipeline de Seguridad — Fluid Attacks

Este documento describe la configuración del pipeline de análisis de seguridad integrado en este repositorio mediante **Fluid Attacks Essentials**, dando cumplimiento al requisito del Componente A del contrato.

---

## Descripción general

El pipeline ejecuta cinco tipos de análisis de seguridad de forma automática sobre cada cambio de código. Está implementado como un workflow de GitHub Actions y se configura centralmente a través del archivo `.github/.fluidattacks.yaml`.

- **SAST, SCA, DAST y Secret Scan** utilizan las GitHub Actions oficiales de Fluid Attacks.
- **Container Scan** utiliza el binario nativo `cs`, instalado en el runner mediante un instalador de un solo comando.

| Análisis | Job | Herramienta |
|---|---|---|
| Análisis estático de código (SAST) | `sast` | `fluidattacks/sast-action@1.3.0` |
| Análisis de composición de software (SCA) | `sca-scan` | `fluidattacks/sca-action@1.2.0` |
| Análisis dinámico de aplicaciones (DAST) | `dast-scan` | `fluidattacks/dast-action@0.2.0` |
| Análisis de imágenes de contenedor (CS) | `container-scan` | Binario nativo `cs` |
| Detección de secretos expuestos (SS) | `secret-scan` | `fluidattacks/ss-action@0.2.0` |

---

## Archivos relevantes

```
.github/
├── workflows/
│   └── security-scans.yml   # Definición del pipeline
├── .fluidattacks.yaml        # Configuración centralizada de todos los escáneres
└── .cs-config.yaml           # Configuración exclusiva del binario cs (container scan)
```

---

## Ejecución automática

El pipeline se activa automáticamente en dos eventos:

```yaml
on:
  push:
    branches:
      - trunk
  pull_request:
    types: [opened, synchronize, reopened]
```

- **Push a `trunk`**: se ejecuta al fusionar cambios en la rama principal.
- **Pull request**: se ejecuta al abrir, actualizar o reabrir cualquier PR, actuando como puerta de calidad antes de la fusión.

Los cinco jobs corren en paralelo, sin dependencias entre sí, lo que minimiza el tiempo total de ejecución del pipeline.

---

## Configuración central: `.github/.fluidattacks.yaml`

Los escáneres SAST, SCA, DAST y Secret Scan leen este archivo. El binario `cs` tiene un archivo de configuración separado (`.github/.cs-config.yaml`) por una restricción técnica explicada más adelante. El archivo actual tiene el siguiente contenido:

```yaml
language: ES
strict: True
output:
  file_path: fluidattacks-results.sarif
  format: SARIF
ss:
  include:
    - .
sca:
  include:
    - .
sast:
  include:
    - .
  exclude:
    - dojo/db_migrations/
dast:
  urls:
    - url: https://d2fut0y3msj4nj.cloudfront.net
containers_sca:
  images:
    - image_uri: alpine:3.17
```

### Parámetros globales

| Parámetro | Valor | Descripción |
|---|---|---|
| `language` | `ES` | Idioma de los reportes generados |
| `strict` | `True` | Los jobs fallan si se encuentran vulnerabilidades |
| `output.format` | `SARIF` | Formato estándar de reporte de seguridad |
| `output.file_path` | `fluidattacks-results.sarif` | Ruta del reporte generado en el runner |

### Resolución de rutas

Las rutas en las secciones `include` y `exclude` (como `.` y `dojo/db_migrations/`) son relativas al directorio de trabajo del escáner, que es la raíz del repositorio en el runner de GitHub Actions.

---

## Jobs del pipeline

### 1. SAST — Análisis estático de código

**Qué hace:** Analiza el código fuente en busca de vulnerabilidades sin ejecutar la aplicación. Detecta inyecciones, manejo inseguro de datos, credenciales en código, vulnerabilidades en Infraestructura como Código (IaC), entre otros.

**Alcance:** Todo el repositorio (`.`), excluyendo `dojo/db_migrations/` para evitar ruido de archivos auto-generados por Django.

```yaml
sast:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4

    - uses: fluidattacks/sast-action@1.3.0
      id: scan
      with:
        scan_config_path: .github/.fluidattacks.yaml
        scanner_mode: full

    - uses: actions/upload-artifact@v4
      with:
        name: sast-results
        path: fluidattacks-results.sarif

    - name: Fail if vulnerabilities found
      if: steps.scan.outputs.vulnerabilities_found == 'true'
      run: exit 1
```

---

### 2. SCA — Análisis de composición de software

**Qué hace:** Examina las dependencias del proyecto contra la base de datos de CVE de Fluid Attacks.

**Alcance:** Todo el repositorio (`.`), para que el escáner detecte automáticamente los manifiestos de dependencias.

```yaml
sca-scan:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4

    - uses: fluidattacks/sca-action@1.2.0
      id: scan
      with:
        scan_config_path: .github/.fluidattacks.yaml
        scanner_mode: full

    - uses: actions/upload-artifact@v4
      with:
        name: sca-results
        path: fluidattacks-results.sarif

    - name: Fail if vulnerabilities found
      if: steps.scan.outputs.vulnerabilities_found == 'true'
      run: exit 1
```

---

### 3. DAST — Análisis dinámico de aplicaciones

**Qué hace:** Realiza pruebas activas contra endpoints URL. Detecta vulnerabilidades como HTTP headers inseguros, suites de cifrado inseguras, entre otras.

**URL objetivo:** `https://d2fut0y3msj4nj.cloudfront.net` — instancia desplegada de la aplicación.

```yaml
dast-scan:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4

    - uses: fluidattacks/dast-action@0.2.0
      id: scan
      with:
        scan_config_path: .github/.fluidattacks.yaml

    - uses: actions/upload-artifact@v4
      with:
        name: dast-results
        path: fluidattacks-results.sarif

    - name: Fail if vulnerabilities found
      if: steps.scan.outputs.vulnerabilities_found == 'true'
      run: exit 1
```

> **Nota de mantenimiento:** Si la URL de la aplicación cambia, actualizar el campo `dast.urls` en `.github/.fluidattacks.yaml`.

---

### 4. Container Scan — Análisis de imagen Docker

**Qué hace:** Analiza los paquetes instalados en imágenes Docker contra la base de datos de CVE de Fluid Attacks. Detecta vulnerabilidades en la cadena de suministro a nivel de contenedor.

**Herramienta:** Binario nativo `cs`, instalado en el runner mediante un único comando curl.

**Configuración separada:** El binario `cs` utiliza `.github/.cs-config.yaml` en lugar del archivo compartido. Esto se debe a que `cs` deserializa el YAML con `deny_unknown_fields`, lo que significa que cualquier clave no reconocida por el binario (`sast`, `sca`, `dast`, `ss`) provoca un error de parseo. El archivo exclusivo solo contiene las claves que `cs` acepta.

El binario requiere al menos una imagen en la lista para correr un análisis.

```yaml
# .github/.cs-config.yaml
language: ES
output:
  file_path: fluidattacks-results.sarif
  format: SARIF
containers_sca:
  images:
    - image_uri: alpine:3.17
```

```yaml
container-scan:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4

    - name: Install cs
      run: curl -fsSL https://public.fluidattacks.com/cs/install.sh | sh

    - name: Run container scan
      run: cs scan --config .github/.cs-config.yaml
```

---

### 5. Secret Scan — Detección de secretos expuestos

**Qué hace:** Recorre el contenido del repositorio en busca de credenciales, tokens, claves API u otros secretos que hayan sido comprometidos accidentalmente.

**Alcance:** Todo el repositorio (`.`).

```yaml
secret-scan:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4

    - uses: fluidattacks/ss-action@0.2.0
      id: scan
      with:
        scan_config_path: .github/.fluidattacks.yaml

    - uses: actions/upload-artifact@v4
      with:
        name: secret-results
        path: fluidattacks-results.sarif

    - name: Fail if vulnerabilities found
      if: steps.scan.outputs.vulnerabilities_found == 'true'
      run: exit 1
```

---

## Gating del pipeline

Los jobs SAST, SCA, DAST y Secret Scan fallan si el escáner reporta hallazgos, usando la salida `vulnerabilities_found` de cada action. El paso de fallo se ejecuta después de la subida del artefacto, garantizando que el reporte SARIF siempre esté disponible para descarga incluso cuando el job falla.

El job de Container Scan también falla si encuentra vulnerabilidades, a través del flag `strict: True` en su configuración.

---

## Resultados

Al completarse cada job, el archivo `fluidattacks-results.sarif` se sube como artefacto de la ejecución del workflow mediante `actions/upload-artifact@v4`. Los artefactos están disponibles en el resumen de la ejecución en GitHub bajo los nombres `sast-results`, `sca-results`, `dast-results` y `secret-results`.

Los resultados también se publican en la plataforma de Fluid Attacks (`app.fluidattacks.com`), donde pueden consultarse, gestionarse y asignarse para remediación.

---

## Operación y mantenimiento

### Agregar imagen del container scan

La lista debe tener al menos una entrada:

```yaml
containers_sca:
  images:
    - image_uri: nombre-imagen:tag
```

### Actualizar la URL objetivo del DAST

Editar el campo `dast.urls` en `.github/.fluidattacks.yaml`:

```yaml
dast:
  urls:
    - url: https://nueva-url-de-la-aplicacion.com
```

### Excluir rutas del análisis (De ser necesario)

Agregar entradas bajo la clave `exclude` del escáner correspondiente en `.github/.fluidattacks.yaml`:

```yaml
sast:
  include:
    - .
  exclude:
    - dojo/db_migrations/
    - tests/
```

### Actualizar versiones de las Actions

Las Actions están ancladas a versiones específicas (`@1.3.0`, `@1.2.0`, `@0.2.0`). Para actualizar, cambiar el tag en el workflow al publicarse una nueva versión.

---

## Requisitos previos para ejecutar el pipeline

| Requisito | Detalle |
|---|---|
| Cuenta en Fluid Attacks | Necesaria para publicar resultados en la plataforma. |
| Runner Ubuntu | Todos los jobs requieren `ubuntu-latest`. Docker está disponible por defecto en estos runners. |
| URL de la aplicación accesible | El DAST requiere que la URL configurada sea alcanzable desde los runners de GitHub Actions. |

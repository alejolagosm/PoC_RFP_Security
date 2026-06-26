# Pipeline de Seguridad — Fluid Attacks

Este documento describe la configuración del pipeline de análisis de seguridad integrado en este repositorio mediante **Fluid Attacks Essentials**, dando cumplimiento al requisito del Componente A del contrato.

---

## Descripción general

El pipeline ejecuta tres tipos de análisis de seguridad de forma automática sobre cada cambio de código. Está implementado como un workflow de GitHub Actions y se configura centralmente a través del archivo `.github/.fluidattacks.yaml`.

| Análisis | Job | Herramienta |
|---|---|---|
| Análisis estático de código (SAST) | `sast` | `fluidattacks/sast-action@1.3.0` |
| Análisis de composición de software (SCA) | `sca-scan` | `fluidattacks/sca-action@1.2.0` |
| Detección de secretos expuestos (SS) | `secret-scan` | `fluidattacks/ss-action@main` |

---

## Archivos relevantes

```
.github/
├── workflows/
│   └── security-scans.yml   # Definición del pipeline
└── .fluidattacks.yaml        # Configuración centralizada de todos los escáneres
```

---

## Ejecución automática

El pipeline se activa automáticamente en pull requests:

```yaml
on:
  pull_request:
    types: [opened, synchronize, reopened]
```

Los tres jobs corren en paralelo, sin dependencias entre sí, lo que minimiza el tiempo total de ejecución del pipeline.

---

## Configuración central: `.github/.fluidattacks.yaml`

Todos los escáneres leen este archivo. El archivo actual tiene el siguiente contenido:

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
      with:
        fetch-depth: 0

    - uses: fluidattacks/sast-action@1.3.0
      id: scan
      with:
        scan_config_path: .github/.fluidattacks.yaml
        scanner_mode: diff

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
      with:
        fetch-depth: 0

    - uses: fluidattacks/sca-action@1.2.0
      id: scan
      with:
        scan_config_path: .github/.fluidattacks.yaml
        scanner_mode: diff

    - uses: actions/upload-artifact@v4
      with:
        name: sca-results
        path: fluidattacks-results.sarif

    - name: Fail if vulnerabilities found
      if: steps.scan.outputs.vulnerabilities_found == 'true'
      run: exit 1
```

---

### 3. Secret Scan — Detección de secretos expuestos

**Qué hace:** Recorre el contenido del repositorio en busca de credenciales, tokens, claves API u otros secretos que hayan sido comprometidos accidentalmente.

**Alcance:** Todo el repositorio (`.`).

```yaml
secret-scan:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0

    - uses: fluidattacks/ss-action@0.3.0
      id: scan
      with:
        scan_config_path: .github/.fluidattacks.yaml
        scanner_mode: diff

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

Los tres jobs fallan si el escáner reporta hallazgos, usando la salida `vulnerabilities_found` de cada action. El paso de fallo se ejecuta después de la subida del artefacto, garantizando que el reporte SARIF siempre esté disponible para descarga incluso cuando el job falla.

---

## Resultados

Al completarse cada job, el archivo `fluidattacks-results.sarif` se sube como artefacto de la ejecución del workflow mediante `actions/upload-artifact@v4`. Los artefactos están disponibles en el resumen de la ejecución en GitHub bajo los nombres `sast-results`, `sca-results` y `secret-results`.

Los resultados también se publican en la plataforma de Fluid Attacks (`app.fluidattacks.com`), donde pueden consultarse, gestionarse y asignarse para remediación.

---

## Operación y mantenimiento

### Excluir rutas del análisis

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

Las Actions están ancladas a versiones específicas (`@1.3.0`, `@1.2.0`). Para actualizar, cambiar el tag en el workflow al publicarse una nueva versión.

---

## Requisitos previos para ejecutar el pipeline

| Requisito | Detalle |
|---|---|
| Cuenta en Fluid Attacks | Necesaria para publicar resultados en la plataforma. |
| Runner Ubuntu | Todos los jobs requieren `ubuntu-latest`. Docker está disponible por defecto en estos runners. |

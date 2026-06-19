"""
Script para crear el General Setting RENDER_ALL_FINDING_V2 en DefectDojo
con todos los roles disponibles en el value.

Si ya existe (conflict 400/409), lo omite sin error.

Uso:
    python create_general_settings.py \
        --host https://<defectdojo-host> \
        --token <api-token-admin>
"""

import argparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERIFY_CERTIFICATE = False

# Todos los roles definidos en el sistema
ALL_ROLES = [
    "API_Importer",
    "Writer",
    "Maintainer",
    "Owner",
    "Reader",
    "Developer",
    "Leader",
    "Cibersecurity",
    "Risk",
]

GENERAL_SETTINGS = [
    {
        "name_key": "RENDER_ALL_FINDING_V2",
        "value": ",".join(ALL_ROLES),
        "category": "FEATURE_FLAG",
        "data_type": "LIST",
        "description": "Se indica los roles los cuales puede ven el boton de view all finding v20",
        "status": True,
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_headers(token):
    return {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
    }


def setting_exists(session, host, token, name_key):
    """Devuelve True si ya existe un GeneralSetting con ese name_key exacto."""
    url = f"{host}/api/v2/general_settings/"
    offset = 0
    limit = 100
    while True:
        resp = session.get(
            url,
            headers=get_headers(token),
            params={"limit": limit, "offset": offset},
            verify=VERIFY_CERTIFICATE,
        )
        if resp.status_code != 200:
            return False
        data = resp.json()
        for item in data.get("results", []):
            if item["name_key"] == name_key:
                return True
        if data.get("next") is None:
            return False
        offset += limit


def create_setting(session, host, token, payload):
    """Crea un GeneralSetting. Devuelve el objeto o None si ya existía."""
    name_key = payload["name_key"]

    if setting_exists(session, host, token, name_key):
        print(f"    [~] Ya existe, se omite: '{name_key}'")
        return None

    url = f"{host}/api/v2/general_settings/"
    resp = session.post(
        url,
        headers=get_headers(token),
        json=payload,
        verify=VERIFY_CERTIFICATE,
    )
    if resp.status_code in (200, 201):
        obj = resp.json()
        obj_id = obj.get("id", "?")
        print(f"    [+] Setting creado: '{name_key}' (id={obj_id})")
        return obj
    # IntegrityError devuelto como 400/409 según el servidor
    if resp.status_code in (400, 409):
        print(f"    [~] Conflicto al crear '{name_key}', probablemente ya existe — se omite.")
        return None
    print(f"    [!] Error al crear '{name_key}': {resp.status_code} {resp.text}")
    resp.raise_for_status()


# ---------------------------------------------------------------------------
# Output table
# ---------------------------------------------------------------------------

def print_summary_table(rows):
    headers = ["name_key", "value", "estado"]
    col_widths = [
        max(len(headers[i]), max(len(r[i]) for r in rows))
        for i in range(len(headers))
    ]
    sep = "+-" + "-+-".join("-" * w for w in col_widths) + "-+"
    row_fmt = "| " + " | ".join(f"{{:<{w}}}" for w in col_widths) + " |"

    print("\n" + sep)
    print(row_fmt.format(*headers))
    print(sep)
    for row in rows:
        print(row_fmt.format(*row))
    print(sep)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Crea General Settings en DefectDojo."
    )
    parser.add_argument(
        "--host",
        required=True,
        help="URL base de DefectDojo (ej: https://localhost:8080)",
    )
    parser.add_argument(
        "--token",
        required=True,
        help="API token de un usuario administrador",
    )
    args = parser.parse_args()

    host = args.host.rstrip("/")
    session = requests.Session()

    table_rows = []

    for payload in GENERAL_SETTINGS:
        name_key = payload["name_key"]
        print(f"[*] Procesando setting: {name_key}")
        result = create_setting(session, host, args.token, payload)
        status = "creado" if result else "ya existía"
        table_rows.append((name_key, payload["value"], status))
        print()

    print("=" * 70)
    print(" RESUMEN DE GENERAL SETTINGS")
    print("=" * 70)
    print_summary_table(table_rows)
    print()


if __name__ == "__main__":
    main()

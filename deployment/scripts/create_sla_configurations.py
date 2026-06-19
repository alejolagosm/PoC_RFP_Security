"""
Script para crear las SLA Configurations en DefectDojo.

Configuraciones creadas:
  Default                  - Critical: 7, High: 30, Medium: 90, Low: 120
  No SLA Enforced          - Sin días (enforce desactivado)
  Orphan                   - Sin días (enforce desactivado)
  RiskAcceptanceExpiration - Critical: 7, High: 30, Medium: 90, Low: 120
  TransferFindingExpiration- Critical: 7, High: 30, Medium: 90, Low: 120

Si alguna ya existe, se omite y se continúa con la siguiente.

Uso:
    python create_sla_configurations.py \
        --host https://<defectdojo-host> \
        --token <api-token-admin>
"""

import argparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERIFY_CERTIFICATE = False

# Campos por configuración SLA.
# None en critical/high/medium/low = sin días configurados (enforce=False)
SLA_CONFIGURATIONS = [
    {
        "name": "Default",
        "description": (
            "The Default SLA Configuration. "
            "Products not using an explicit SLA Configuration will use this one."
        ),
        "critical": 7,   "enforce_critical": True,
        "high":    30,   "enforce_high":    True,
        "medium":  90,   "enforce_medium":  True,
        "low":    120,   "enforce_low":     True,
    },
    {
        "name": "No SLA Enforced",
        "description": "No SLA is enforced for a product which uses this SLA configuration.",
        "critical": 7,   "enforce_critical": False,
        "high":    30,   "enforce_high":    False,
        "medium":  90,   "enforce_medium":  False,
        "low":    120,   "enforce_low":     False,
    },
    {
        "name": "Orphan",
        "description": "",
        "critical": 7,   "enforce_critical": False,
        "high":    30,   "enforce_high":    False,
        "medium":  90,   "enforce_medium":  False,
        "low":    120,   "enforce_low":     False,
    },
    {
        "name": "RiskAcceptanceExpiration",
        "description": "",
        "critical": 7,   "enforce_critical": True,
        "high":    30,   "enforce_high":    True,
        "medium":  90,   "enforce_medium":  True,
        "low":    120,   "enforce_low":     True,
    },
    {
        "name": "TransferFindingExpiration",
        "description": "",
        "critical": 7,   "enforce_critical": True,
        "high":    30,   "enforce_high":    True,
        "medium":  90,   "enforce_medium":  True,
        "low":    120,   "enforce_low":     True,
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


def sla_exists(session, host, token, name):
    """Devuelve True si ya existe una SLA Configuration con ese nombre exacto."""
    url = f"{host}/api/v2/sla_configurations/"
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
            if item["name"] == name:
                return True
        if data.get("next") is None:
            return False
        offset += limit


def create_sla(session, host, token, config):
    """Crea una SLA Configuration. Devuelve el objeto creado o None si ya existía."""
    name = config["name"]

    if sla_exists(session, host, token, name):
        print(f"    [~] Ya existe, se omite: '{name}'")
        return None

    url = f"{host}/api/v2/sla_configurations/"
    payload = {k: v for k, v in config.items() if v != ""}
    resp = session.post(
        url,
        headers=get_headers(token),
        json=payload,
        verify=VERIFY_CERTIFICATE,
    )
    if resp.status_code == 201:
        obj = resp.json()
        print(f"    [+] SLA creada: '{name}' (id={obj['id']})")
        return obj
    print(f"    [!] Error al crear '{name}': {resp.status_code} {resp.text}")
    resp.raise_for_status()


# ---------------------------------------------------------------------------
# Output table
# ---------------------------------------------------------------------------

def print_summary_table(rows):
    headers = ["Nombre", "Critical", "High", "Medium", "Low", "Estado"]
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
        description="Crea SLA Configurations en DefectDojo."
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

    for config in SLA_CONFIGURATIONS:
        name = config["name"]
        print(f"[*] Procesando SLA: {name}")
        result = create_sla(session, host, args.token, config)

        enforce = config.get("enforce_critical", False)
        critical_str = str(config["critical"]) if enforce else "-"
        high_str     = str(config["high"])     if config.get("enforce_high")   else "-"
        medium_str   = str(config["medium"])   if config.get("enforce_medium") else "-"
        low_str      = str(config["low"])      if config.get("enforce_low")    else "-"
        status       = "creada" if result else "ya existía"

        table_rows.append((name, critical_str, high_str, medium_str, low_str, status))
        print()

    print("=" * 70)
    print(" RESUMEN DE SLA CONFIGURATIONS")
    print("=" * 70)
    print_summary_table(table_rows)
    print()


if __name__ == "__main__":
    main()

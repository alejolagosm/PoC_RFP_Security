"""
Script para crear los grupos de DefectDojo con su rol global asignado.

Grupos creados:
  Approvers_Cybersecurity  -> Cibersecurity
  Approvers_Risk           -> Risk
  Compliance               -> Cibersecurity
  Reclassify_Orphans       -> (sin rol)
  Reviewer_Risk            -> Risk
  Reviewers_Maintainer     -> (sin rol)
  Reviewers_c2c            -> Cibersecurity
  Reviewers_devsecops_hacker -> (sin rol)
  Reviewers_prisma         -> Cibersecurity
  Reviewers_tenable        -> Cibersecurity

Uso:
    python create_groups.py \
        --host https://<defectdojo-host> \
        --token <api-token-admin>
"""

import argparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERIFY_CERTIFICATE = False

# (nombre_grupo, rol_global_o_None)
GROUPS_TO_CREATE = [
    ("Approvers_Cybersecurity",     "Cibersecurity"),
    ("Approvers_Risk",              "Risk"),
    ("Compliance",                  "Cibersecurity"),
    ("Reclassify_Orphans",          None),
    ("Reviewer_Risk",               "Risk"),
    ("Reviewers_Maintainer",        None),
    ("Reviewers_c2c",               "Cibersecurity"),
    ("Reviewers_devsecops_hacker",  None),
    ("Reviewers_prisma",            "Cibersecurity"),
    ("Reviewers_tenable",           "Cibersecurity"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_headers(token):
    return {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
    }


# ---------------------------------------------------------------------------
# API calls
# ---------------------------------------------------------------------------

def get_all_roles(session, host, token):
    """Devuelve un dict {nombre_rol: id_rol}."""
    url = f"{host}/api/v2/roles/"
    resp = session.get(
        url,
        headers=get_headers(token),
        params={"limit": 100},
        verify=VERIFY_CERTIFICATE,
    )
    resp.raise_for_status()
    return {r["name"]: r["id"] for r in resp.json()["results"]}


def get_existing_group(session, host, token, name):
    """Busca un grupo por nombre y lo devuelve si existe, o None."""
    url = f"{host}/api/v2/dojo_groups/"
    resp = session.get(
        url,
        headers=get_headers(token),
        params={"name": name, "limit": 1},
        verify=VERIFY_CERTIFICATE,
    )
    if resp.status_code == 200 and resp.json().get("count", 0) > 0:
        return resp.json()["results"][0]
    return None


def create_group(session, host, token, name):
    """Crea un Dojo Group y devuelve el objeto creado.
    Si ya existe, devuelve el grupo existente y continúa."""
    url = f"{host}/api/v2/dojo_groups/"
    resp = session.post(
        url,
        headers=get_headers(token),
        json={"name": name},
        verify=VERIFY_CERTIFICATE,
    )
    if resp.status_code == 201:
        group = resp.json()
        print(f"    [+] Grupo creado: '{name}' (id={group['id']})")
        return group
    if resp.status_code == 400:
        existing = get_existing_group(session, host, token, name)
        if existing:
            print(f"    [~] Grupo ya existente, se omite: '{name}' (id={existing['id']})")
            return None
    print(f"    [!] Error al crear grupo '{name}': {resp.status_code} {resp.text}")
    resp.raise_for_status()


def assign_global_role_to_group(session, host, token, group_id, role_id, role_name):
    """Asigna un rol global a un grupo."""
    url = f"{host}/api/v2/global_roles/"
    resp = session.post(
        url,
        headers=get_headers(token),
        json={"group": group_id, "role": role_id},
        verify=VERIFY_CERTIFICATE,
    )
    if resp.status_code == 201:
        gr = resp.json()
        print(f"    [+] Rol global asignado: '{role_name}' (global_role_id={gr['id']})")
        return gr
    print(
        f"    [!] Error al asignar rol '{role_name}' al grupo id={group_id}: "
        f"{resp.status_code} {resp.text}"
    )
    resp.raise_for_status()


# ---------------------------------------------------------------------------
# Output table
# ---------------------------------------------------------------------------

def print_summary_table(rows):
    headers = ["Grupo", "Rol Global"]
    col_widths = [
        max(len(headers[0]), max(len(r[0]) for r in rows)),
        max(len(headers[1]), max(len(r[1]) for r in rows)),
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
        description="Crea grupos en DefectDojo y les asigna rol global."
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

    print("[*] Consultando roles disponibles en DefectDojo...")
    all_roles = get_all_roles(session, host, args.token)
    print(f"    Roles encontrados: {sorted(all_roles.keys())}\n")

    table_rows = []

    for group_name, role_name in GROUPS_TO_CREATE:
        print(f"[*] Creando grupo: {group_name}")
        group = create_group(session, host, args.token, group_name)

        if group is None:
            table_rows.append((group_name, "(ya existía — omitido)"))
            print()
            continue

        if role_name:
            role_id = all_roles.get(role_name)
            if role_id is None:
                print(f"    [!] Rol '{role_name}' no encontrado — grupo creado sin rol.")
                table_rows.append((group_name, f"[NOT FOUND] {role_name}"))
            else:
                assign_global_role_to_group(
                    session, host, args.token, group["id"], role_id, role_name
                )
                table_rows.append((group_name, role_name))
        else:
            print(f"    [-] Sin rol global asignado.")
            table_rows.append((group_name, "(ninguno)"))

        print()

    print("=" * 60)
    print(" RESUMEN DE GRUPOS CREADOS")
    print("=" * 60)
    print_summary_table(table_rows)
    print()


if __name__ == "__main__":
    main()

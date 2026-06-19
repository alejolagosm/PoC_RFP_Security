"""
Script para crear un usuario en DefectDojo por cada rol disponible
y asignarle ese rol a nivel global.

Roles creados:
  Cibersecurity, Developer, Leader

Uso:
    python create_users_by_role.py \
        --host https://<defectdojo-host> \
        --token <api-token-admin>

"""

import argparse
import secrets
import string

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERIFY_CERTIFICATE = False

ROLES_TO_CREATE = [
    "Cibersecurity",
    "Developer",
    "Leader",
    "Maintainer",
    "Risk"
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_headers(token):
    return {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
    }


def generate_password(length=16):
    """Genera una contraseña segura con letras, dígitos y símbolos."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*" for c in password)
        ):
            return password


# ---------------------------------------------------------------------------
# API calls
# ---------------------------------------------------------------------------

def get_all_roles(session, host, token):
    """Devuelve un dict {nombre_rol: id_rol} con todos los roles disponibles."""
    url = f"{host}/api/v2/roles/"
    resp = session.get(
        url,
        headers=get_headers(token),
        params={"limit": 100},
        verify=VERIFY_CERTIFICATE,
    )
    resp.raise_for_status()
    return {r["name"]: r["id"] for r in resp.json()["results"]}


def create_user(session, host, token, username, password, first_name, last_name, email):
    """Crea un usuario en DefectDojo y devuelve el objeto creado."""
    url = f"{host}/api/v2/users/"
    payload = {
        "username": username,
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "password": password,
        "is_active": True,
        "is_superuser": False,
    }
    resp = session.post(
        url,
        headers=get_headers(token),
        json=payload,
        verify=VERIFY_CERTIFICATE,
    )
    if resp.status_code == 201:
        user = resp.json()
        print(f"    [+] Usuario creado: '{username}' (id={user['id']})")
        return user
    print(f"    [!] Error al crear usuario '{username}': {resp.status_code} {resp.text}")
    resp.raise_for_status()


def assign_global_role(session, host, token, user_id, role_id, role_name):
    """Asigna un rol global a un usuario."""
    url = f"{host}/api/v2/global_roles/"
    payload = {
        "user": user_id,
        "role": role_id,
    }
    resp = session.post(
        url,
        headers=get_headers(token),
        json=payload,
        verify=VERIFY_CERTIFICATE,
    )
    if resp.status_code == 201:
        gr = resp.json()
        print(f"    [+] Rol global asignado: '{role_name}' (global_role_id={gr['id']})")
        return gr
    print(
        f"    [!] Error al asignar rol '{role_name}' a user_id={user_id}: "
        f"{resp.status_code} {resp.text}"
    )
    resp.raise_for_status()


# ---------------------------------------------------------------------------
# Output table
# ---------------------------------------------------------------------------

def print_summary_table(rows):
    """Imprime una tabla con usuario, contraseña, rol y email."""
    headers = ["Usuario", "Contraseña", "Rol", "Email"]
    col_widths = [
        max(len(headers[0]), max(len(r[0]) for r in rows)),
        max(len(headers[1]), max(len(r[1]) for r in rows)),
        max(len(headers[2]), max(len(r[2]) for r in rows)),
        max(len(headers[3]), max(len(r[3]) for r in rows)),
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
        description="Crea un usuario por cada rol en DefectDojo y asigna el rol globalmente."
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
    skipped = []

    for role_name in ROLES_TO_CREATE:
        role_id = all_roles.get(role_name)
        if role_id is None:
            print(f"[!] Rol '{role_name}' no encontrado — se omite.\n")
            skipped.append(role_name)
            continue

        username = f"user_{role_name.lower()}"
        password = generate_password()
        email = f"{username}@demo.defectdojo.local"
        first_name = role_name.replace("_", " ").title()
        last_name = "Demo"

        print(f"[*] Creando usuario para rol: {role_name}")
        user = create_user(
            session, host, args.token,
            username, password, first_name, last_name, email,
        )
        assign_global_role(session, host, args.token, user["id"], role_id, role_name)

        table_rows.append((username, password, role_name, email))
        print()

    # Summary
    print("=" * 70)
    print(" RESUMEN DE USUARIOS CREADOS")
    print("=" * 70)

    if table_rows:
        print_summary_table(table_rows)
    else:
        print("  No se creó ningún usuario.")

    if skipped:
        print(f"\n[!] Roles omitidos (no encontrados en la instancia): {skipped}")

    print()


if __name__ == "__main__":
    main()

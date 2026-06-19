"""
Script para poblar DefectDojo con datos de prueba:
  - 3 Product Types
  - 5 Products por Product Type
  - 10 Engagements por Product (nombres de microservicios)
  - N Tests por Engagement (distintos scan types)
  - Findings de ejemplo distribuidos entre los tests

Uso:
    python populate_defectdojo.py \
        --host https://<defectdojo-host> \
        --token <api-token>
"""

import argparse
import random
from datetime import datetime, timedelta

import requests

VERIFY_CERTIFICATE = False


def get_headers(token):
    return {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
    }


# ---------------------------------------------------------------------------
# Product Types
# ---------------------------------------------------------------------------

def create_product_type(session, host, token, name, description):
    url = f"{host}/api/v2/product_types/"
    payload = {"name": name, "description": description}
    resp = session.post(url, headers=get_headers(token), json=payload, verify=VERIFY_CERTIFICATE)
    if resp.status_code == 201:
        pt = resp.json()
        print(f"  [+] Product Type created: '{pt['name']}' (id={pt['id']})")
        return pt
    print(f"  [!] Error creating Product Type '{name}': {resp.status_code} {resp.text}")
    resp.raise_for_status()


# ---------------------------------------------------------------------------
# Products
# ---------------------------------------------------------------------------

def create_product(session, host, token, name, description, product_type_id):
    url = f"{host}/api/v2/products/"
    payload = {
        "name": name,
        "description": description,
        "prod_type": product_type_id,
    }
    resp = session.post(url, headers=get_headers(token), json=payload, verify=VERIFY_CERTIFICATE)
    if resp.status_code == 201:
        p = resp.json()
        print(f"    [+] Product created: '{p['name']}' (id={p['id']})")
        return p
    print(f"    [!] Error creating Product '{name}': {resp.status_code} {resp.text}")
    resp.raise_for_status()


# ---------------------------------------------------------------------------
# Engagements
# ---------------------------------------------------------------------------

def create_engagement(session, host, token, name, description, product_id, index):
    url = f"{host}/api/v2/engagements/"
    today = datetime.now().date()
    end = today + timedelta(days=30)
    payload = {
        "name": name,
        "description": description,
        "product": product_id,
        "engagement_type": "CI/CD",
        "status": "In Progress",
        "target_start": str(today),
        "target_end": str(end),
        "build_id": f"BUILD-{index:04d}",
        "branch_tag": "trunk",
        "commit_hash": f"abc{index:04x}def",
    }
    resp = session.post(url, headers=get_headers(token), json=payload, verify=VERIFY_CERTIFICATE)
    if resp.status_code == 201:
        e = resp.json()
        print(f"      [+] Engagement created: '{e['name']}' (id={e['id']})")
        return e
    print(f"      [!] Error creating Engagement '{name}': {resp.status_code} {resp.text}")
    resp.raise_for_status()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

SCAN_TYPES = [
    "Trivy Scan",
    "Semgrep JSON Report",
    "Checkov Scan",
    "OWASP ZAP Scan",
]

# Cache para no re-consultar el mismo test type
_test_type_cache = {}

def get_or_create_test_type(session, host, token, name):
    if name in _test_type_cache:
        return _test_type_cache[name]

    headers = get_headers(token)
    # Buscar por nombre
    resp = session.get(f"{host}/api/v2/test_types/", headers=headers,
                       params={"name": name}, verify=VERIFY_CERTIFICATE)
    if resp.status_code == 200 and resp.json().get("count", 0) > 0:
        tt_id = resp.json()["results"][0]["id"]
        _test_type_cache[name] = tt_id
        return tt_id

    # Crear si no existe
    resp = session.post(f"{host}/api/v2/test_types/", headers=headers,
                        json={"name": name}, verify=VERIFY_CERTIFICATE)
    if resp.status_code == 201:
        tt_id = resp.json()["id"]
        _test_type_cache[name] = tt_id
        print(f"        [+] Test Type created: '{name}' (id={tt_id})")
        return tt_id

    print(f"        [!] Error resolving Test Type '{name}': {resp.status_code} {resp.text}")
    resp.raise_for_status()


def create_test(session, host, token, engagement_id, scan_type, title):
    url = f"{host}/api/v2/tests/"
    today = datetime.now().date()
    test_type_id = get_or_create_test_type(session, host, token, scan_type)
    payload = {
        "engagement": engagement_id,
        "test_type": test_type_id,
        "title": title,
        "target_start": str(today),
        "target_end": str(today + timedelta(days=1)),
    }
    resp = session.post(url, headers=get_headers(token), json=payload, verify=VERIFY_CERTIFICATE)
    if resp.status_code == 201:
        t = resp.json()
        print(f"        [+] Test created: '{t['title']}' scan_type='{scan_type}' (id={t['id']})")
        return t
    print(f"        [!] Error creating Test '{title}': {resp.status_code} {resp.text}")
    resp.raise_for_status()


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

FINDING_TEMPLATES = [
    {
        "title": "Dependency with known CVE",
        "description": "A third-party dependency has a publicly known vulnerability (CVE).",
        "severity": "Critical",
        "cwe": 1035,
        "vuln_id_from_tool": "CVE-2021-44228",
        "component_name": "log4j-core",
        "component_version": "2.14.1",
    },
    {
        "title": "Hardcoded credentials in source code",
        "description": "A password or API key was found hardcoded in the source code.",
        "severity": "Critical",
        "cwe": 798,
        "vuln_id_from_tool": "SECRET-001",
        "component_name": None,
        "component_version": None,
    },
    {
        "title": "SQL Injection vulnerability",
        "description": "User-supplied input is not sanitized before being used in a SQL query.",
        "severity": "High",
        "cwe": 89,
        "vuln_id_from_tool": "SQLI-001",
        "component_name": None,
        "component_version": None,
    },
    {
        "title": "Outdated TLS version in use",
        "description": "The service accepts TLS 1.0 or 1.1 connections which are deprecated.",
        "severity": "High",
        "cwe": 326,
        "vuln_id_from_tool": "TLS-WEAK-001",
        "component_name": None,
        "component_version": None,
    },
    {
        "title": "Missing HTTP security headers",
        "description": "Important security headers such as Content-Security-Policy are absent.",
        "severity": "Medium",
        "cwe": 693,
        "vuln_id_from_tool": "HEADER-001",
        "component_name": None,
        "component_version": None,
    },
    {
        "title": "Insecure deserialization",
        "description": "The application deserializes untrusted data without proper validation.",
        "severity": "High",
        "cwe": 502,
        "vuln_id_from_tool": "DESER-001",
        "component_name": None,
        "component_version": None,
    },
    {
        "title": "Cross-Site Scripting (XSS)",
        "description": "Reflected XSS found in a query parameter that is rendered without escaping.",
        "severity": "Medium",
        "cwe": 79,
        "vuln_id_from_tool": "XSS-001",
        "component_name": None,
        "component_version": None,
    },
    {
        "title": "Exposed debug endpoint",
        "description": "A /debug or /actuator endpoint is reachable without authentication.",
        "severity": "Medium",
        "cwe": 200,
        "vuln_id_from_tool": "DEBUG-001",
        "component_name": None,
        "component_version": None,
    },
    {
        "title": "Dependency with medium-severity CVE",
        "description": "A transitive dependency contains a medium-severity vulnerability.",
        "severity": "Medium",
        "cwe": 1035,
        "vuln_id_from_tool": "CVE-2022-22965",
        "component_name": "spring-webmvc",
        "component_version": "5.3.17",
    },
    {
        "title": "Verbose error messages",
        "description": "Stack traces or internal paths are returned to the client on errors.",
        "severity": "Low",
        "cwe": 209,
        "vuln_id_from_tool": "INFO-001",
        "component_name": None,
        "component_version": None,
    },
    {
        "title": "Missing rate limiting on login endpoint",
        "description": "No rate limiting or CAPTCHA is enforced on the authentication endpoint.",
        "severity": "Low",
        "cwe": 307,
        "vuln_id_from_tool": "AUTH-RATE-001",
        "component_name": None,
        "component_version": None,
    },
    {
        "title": "Insecure cookie attributes",
        "description": "Session cookies are missing the Secure and HttpOnly flags.",
        "severity": "Low",
        "cwe": 614,
        "vuln_id_from_tool": "COOKIE-001",
        "component_name": None,
        "component_version": None,
    },
]

FINDING_STATUSES = ["Active", "Active", "Active", "Mitigated", "False Positive"]


def create_finding(session, host, token, test_id, test_type_id, template, index):
    url = f"{host}/api/v2/findings/"
    today = str(datetime.now().date())
    status = random.choice(FINDING_STATUSES)
    is_false_positive = status == "False Positive"
    payload = {
        "test": test_id,
        "found_by": [test_type_id],
        "title": f"{template['title']} [{index:04d}]",
        "description": template["description"],
        "severity": template["severity"],
        "cwe": template.get("cwe"),
        "vuln_id_from_tool": template.get("vuln_id_from_tool", ""),
        "active": status == "Active",
        "verified": False if is_false_positive else random.choice([True, False]),
        "false_p": is_false_positive,
        "is_mitigated": status == "Mitigated",
        "date": today,
        "numerical_severity": f"S{['Critical','High','Medium','Low','Info'].index(template['severity']) + 1}",
    }
    if template.get("component_name"):
        payload["component_name"] = template["component_name"]
        payload["component_version"] = template["component_version"]

    resp = session.post(url, headers=get_headers(token), json=payload, verify=VERIFY_CERTIFICATE)
    if resp.status_code == 201:
        f = resp.json()
        print(f"          [+] Finding: '{template['title']}' severity={template['severity']} status={status} (id={f['id']})")
        return f
    print(f"          [!] Error creating Finding '{template['title']}': {resp.status_code} {resp.text}")
    resp.raise_for_status()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

PRODUCT_TYPES = [
    {"name": "Backend Services",   "description": "Microservicios y APIs del backend"},
    {"name": "Frontend Apps",      "description": "Aplicaciones web y móviles"},
    {"name": "Infrastructure",     "description": "Infraestructura como código y plataforma"},
]

PRODUCTS_TEMPLATE = [
    ("Auth Service",        "Servicio de autenticación y autorización"),
    ("Payments Service",    "Servicio de procesamiento de pagos"),
    ("Notifications API",   "API de notificaciones push y email"),
    ("Reporting Module",    "Módulo de reportes y métricas"),
    ("Data Pipeline",       "Pipeline de ingesta y transformación de datos"),
]

ENGAGEMENTS_TEMPLATE = [
    "ms-user-management",
    "ms-auth-gateway",
    "ms-payment-processor",
    "ms-notification-sender",
    "ms-order-service",
    "ms-inventory-service",
    "ms-billing-service",
    "ms-reporting-engine",
    "ms-config-server",
    "ms-api-gateway",
]


def main():
    parser = argparse.ArgumentParser(description="Poblar DefectDojo con datos de prueba")
    parser.add_argument("--host",  required=True, help="URL base de DefectDojo, ej: https://demo.defectdojo.org")
    parser.add_argument("--token", required=True, help="API Token de DefectDojo")
    parser.add_argument(
        "--no-verify",
        action="store_true",
        default=True,
        help="Deshabilitar verificación SSL (por defecto deshabilitado)",
    )
    args = parser.parse_args()

    host = args.host.rstrip("/")

    session = requests.Session()

    print(f"\nConectando a: {host}\n{'='*60}")

    global_eng_index = 1
    global_finding_index = 1
    created_summary = {"product_types": 0, "products": 0, "engagements": 0, "tests": 0, "findings": 0}

    for pt_data in PRODUCT_TYPES:
        print(f"\nProduct Type: {pt_data['name']}")
        pt = create_product_type(session, host, args.token, pt_data["name"], pt_data["description"])
        created_summary["product_types"] += 1

        for prod_name, prod_desc in PRODUCTS_TEMPLATE:
            full_prod_name = f"{pt_data['name']} - {prod_name}"
            prod = create_product(session, host, args.token, full_prod_name, prod_desc, pt["id"])
            created_summary["products"] += 1

            for eng_name in ENGAGEMENTS_TEMPLATE:
                eng = create_engagement(session, host, args.token, eng_name, f"Microservicio {eng_name}", prod["id"], global_eng_index)
                created_summary["engagements"] += 1
                global_eng_index += 1

                # 1 test por cada scan type disponible
                findings_pool = list(FINDING_TEMPLATES)
                random.shuffle(findings_pool)
                chunks = [findings_pool[i::len(SCAN_TYPES)] for i in range(len(SCAN_TYPES))]

                for idx, scan_type in enumerate(SCAN_TYPES):
                    test_title = f"{eng_name} - {scan_type}"
                    test = create_test(session, host, args.token, eng["id"], scan_type, test_title)
                    created_summary["tests"] += 1
                    test_type_id = _test_type_cache[scan_type]

                    for tmpl in chunks[idx]:
                        create_finding(session, host, args.token, test["id"], test_type_id, tmpl, global_finding_index)
                        created_summary["findings"] += 1
                        global_finding_index += 1
                global_eng_index += 1

    print(f"\n{'='*60}")
    print(f"Resumen de creacion:")
    print(f"  Product Types : {created_summary['product_types']}")
    print(f"  Products      : {created_summary['products']}")
    print(f"  Engagements   : {created_summary['engagements']}")
    print(f"  Tests         : {created_summary['tests']}")
    print(f"  Findings      : {created_summary['findings']}")
    print("Listo!")


if __name__ == "__main__":
    main()

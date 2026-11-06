#!/usr/bin/env python3
# ============================================================
#  API_KEYS.py
#  Registro centralizado de claves de API para el framework.
# ============================================================

import argparse
import json
import os
import sys
from pathlib import Path

import yaml


class _ArgumentParser(argparse.ArgumentParser):
    """ArgumentParser que trata los errores de uso como código 1, no 2."""

    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"❌ {message}", file=sys.stderr)
        sys.exit(1)


# ─── Registro ───

def _framework_root():
    """Resuelve la raíz del framework desde la ubicación de este script."""
    return Path(__file__).resolve().parents[2]


REGISTRO = Path(
    os.environ.get(
        "KEYS_FILE",
        _framework_root() / "00_Config" / "credentials" / "api-keys.yaml",
    )
)

DEFAULT_HARVESTER_TEMPLATE = Path(
    "/usr/lib/python3/dist-packages/theHarvester/api-keys.yaml"
)


def _harvester_template_path():
    """Devuelve la plantilla de theHarvester a usar."""
    if "KEYS_HARVESTER_TEMPLATE" in os.environ:
        return Path(os.environ["KEYS_HARVESTER_TEMPLATE"])
    return DEFAULT_HARVESTER_TEMPLATE


def _cargar_plantilla_theharvester():
    """Carga la plantilla de huecos de theHarvester."""
    path = _harvester_template_path()
    if not path.exists():
        if "KEYS_HARVESTER_TEMPLATE" not in os.environ:
            print(f"⚠️  Plantilla de theHarvester no encontrada: {path}", file=sys.stderr)
        return {}
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as exc:
        print(f"⚠️  Plantilla de theHarvester ilegible: {exc}", file=sys.stderr)
        return {}
    return data.get("apikeys", {})


def _campos_theharvester(plantilla):
    """Construye las rutas con puntos de los huecos de theHarvester."""
    campos = []
    for slot, leaves in plantilla.items():
        if not isinstance(leaves, dict):
            continue
        for leaf in leaves.keys():
            campos.append(f"{slot}.{leaf}")
    return campos


# Campos por defecto de theHarvester si la plantilla instalada no está disponible.
_DEFAULT_HARVESTER_CAMPOS = [
    "bevigil.key", "bitbucket.key", "brave.key", "bufferoverun.key",
    "builtwith.key", "censys.id", "censys.secret", "criminalip.key",
    "dehashed.key", "dnsdumpster.key", "fofa.key", "fofa.email",
    "fullhunt.key", "github.key", "hackertarget.key", "haveibeenpwned.key",
    "hunter.key", "hunterhow.key", "intelx.key", "leakix.key",
    "leaklookup.key", "netlas.key", "onyphe.key", "pentestTools.key",
    "projectDiscovery.key", "rocketreach.key", "securityscorecard.key",
    "securityTrails.key", "shodan.key", "tomba.key", "tomba.secret",
    "venacus.key", "virustotal.key", "whoisxml.key", "windvane.key",
    "zoomeye.key",
]


def _construir_herramientas():
    """Construye la tabla de herramientas, campos incluidos."""
    ht_plantilla = _cargar_plantilla_theharvester()
    ht_campos = _campos_theharvester(ht_plantilla) or _DEFAULT_HARVESTER_CAMPOS
    return [
        {"nombre": "theharvester", "etiqueta": "theHarvester", "campos": ht_campos},
        {"nombre": "shodan", "etiqueta": "Shodan", "campos": ["key"]},
        {
            "nombre": "h8mail",
            "etiqueta": "h8mail",
            "campos": [
                "hunterio", "snusbase_token", "weleakinfo_priv", "weleakinfo_pub",
                "hibp", "leak-lookup_pub", "leak-lookup_priv", "emailrep",
                "dehashed_email", "dehashed_key", "intelx_key", "intelx_maxfile",
                "breachdirectory_user", "breachdirectory_pass",
            ],
        },
        {
            "nombre": "amass",
            "etiqueta": "Amass",
            "campos": [
                "shodan.key", "censys.id", "censys.secret", "securitytrails.key",
                "virustotal.key", "urlscan.key",
            ],
        },
        {
            "nombre": "recon-ng",
            "etiqueta": "recon-ng",
            "campos": [
                "shodan_api", "censys_api_id", "censys_api_secret",
                "securitytrails_api", "virustotal_api", "hunter_api", "github_api",
            ],
        },
        {
            "nombre": "spiderfoot",
            "etiqueta": "SpiderFoot",
            "campos": [
                "sfp_shodan.api_key", "sfp_censys.api_key",
                "sfp_securitytrails.api_key", "sfp_virustotal.api_key",
                "sfp_hunter.api_key", "sfp_urlscan.api_key",
            ],
        },
    ]


HERRAMIENTAS = _construir_herramientas()


def _tool_by_name(nombre):
    for h in HERRAMIENTAS:
        if h["nombre"] == nombre:
            return h
    return None


def _get_nested(d, path):
    """Devuelve (valor, ok) para una ruta con puntos dentro de un dict."""
    for part in path.split("."):
        if not isinstance(d, dict) or part not in d:
            return None, False
        d = d[part]
    return d, True


def _set_nested(d, path, valor):
    """Establece el valor en una ruta con puntos, creando dicts intermedios."""
    parts = path.split(".")
    for part in parts[:-1]:
        if part not in d or not isinstance(d[part], dict):
            d[part] = {}
        d = d[part]
    d[parts[-1]] = valor


def _has_path(d, path):
    _, ok = _get_nested(d, path)
    return ok


def cargar_registro():
    """Carga el registro YAML; si no existe, devuelve la estructura inicial."""
    if not REGISTRO.exists():
        return {"version": 1}
    try:
        with open(REGISTRO) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        print(f"❌ Registro ilegible: {exc}", file=sys.stderr)
        sys.exit(2)
    except OSError as exc:
        print(f"❌ No se pudo leer el registro: {exc}", file=sys.stderr)
        sys.exit(2)
    if data is None:
        return {"version": 1}
    if not isinstance(data, dict):
        print("❌ Registro ilegible: el contenido no es un diccionario", file=sys.stderr)
        sys.exit(2)
    return data


def guardar_registro(reg):
    """Guarda el registro de forma atómica con permisos restrictivos."""
    tmp_path = REGISTRO.with_suffix(".tmp")
    try:
        REGISTRO.parent.mkdir(parents=True, exist_ok=True)
        REGISTRO.parent.chmod(0o700)
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                yaml.safe_dump(
                    reg, f, default_flow_style=False,
                    sort_keys=False, allow_unicode=True,
                )
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        os.replace(tmp_path, REGISTRO)
        REGISTRO.chmod(0o600)
    except OSError as exc:
        print(f"❌ No se pudo escribir el registro: {exc}", file=sys.stderr)
        sys.exit(2)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def _normalizar_valor(valor):
    """Recorta espacios y rechaza saltos de línea y NUL."""
    valor = valor.strip()
    if "\n" in valor or "\0" in valor:
        raise ValueError("valor inválido")
    return valor


def poner_valor(reg, herramienta, campo, valor):
    """Escribe un campo en el registro. Rechaza herramienta/campo desconocidos."""
    tool = _tool_by_name(herramienta)
    if tool is None:
        print(f"❌ Herramienta desconocida: {herramienta}", file=sys.stderr)
        sys.exit(1)
    if campo not in tool["campos"]:
        print(f"❌ Campo desconocido: {herramienta}.{campo}", file=sys.stderr)
        sys.exit(1)
    try:
        valor = _normalizar_valor(valor)
    except ValueError:
        print(
            "❌ El valor no puede contener saltos de línea ni caracteres nulos",
            file=sys.stderr,
        )
        sys.exit(1)
    if "version" not in reg:
        reg["version"] = 1
    if herramienta not in reg:
        reg[herramienta] = {}
    if valor == "-":
        _set_nested(reg[herramienta], campo, "")
    else:
        _set_nested(reg[herramienta], campo, valor)


def sembrar_theharvester(reg):
    """Siembra los huecos de theHarvester desde su plantilla sin pisar lo existente."""
    plantilla = _cargar_plantilla_theharvester()
    if not plantilla:
        return []
    if "theharvester" not in reg:
        reg["theharvester"] = {}
    creados = []
    for slot, leaves in plantilla.items():
        if not isinstance(leaves, dict):
            continue
        for leaf in leaves.keys():
            path = f"{slot}.{leaf}"
            if not _has_path(reg["theharvester"], path):
                _set_nested(reg["theharvester"], path, "")
                creados.append(path)
    return creados


# ─── Adaptadores ───
# Los adaptadores por herramienta se añadirán en tareas posteriores.


# ─── CLI ───

def _longitud_valor(valor):
    return len(valor) if isinstance(valor, str) else 0


def estado_json(reg):
    """Devuelve el estado del registro sin escribir ni revelar secretos."""
    herramientas = []
    for h in HERRAMIENTAS:
        seccion = reg.get(h["nombre"], {})
        campos_json = []
        puestas = 0
        for campo in h["campos"]:
            val, ok = _get_nested(seccion, campo)
            longitud = _longitud_valor(val) if ok else 0
            puesta = longitud > 0
            if puesta:
                puestas += 1
            campos_json.append({
                "campo": campo,
                "puesta": puesta,
                "longitud": longitud,
            })
        herramientas.append({
            "nombre": h["nombre"],
            "etiqueta": h["etiqueta"],
            "puestas": puestas,
            "total": len(h["campos"]),
            "campos": campos_json,
        })
    return {"herramientas": herramientas}


def _mostrar_estado(reg):
    print("\n🔐 ESTADO DE CLAVES DE API")
    print("=" * 50)
    for h in estado_json(reg)["herramientas"]:
        print(f"  {h['etiqueta']}: {h['puestas']}/{h['total']}")


def main():
    parser = _ArgumentParser(
        description="Registro centralizado de claves de API",
    )
    subparsers = parser.add_subparsers(dest="orden")

    poner_parser = subparsers.add_parser("poner", help="Establece un valor")
    poner_parser.add_argument("herramienta")
    poner_parser.add_argument("campo")
    poner_parser.add_argument("valor", nargs="?", default=None)
    poner_parser.add_argument("--stdin", action="store_true")

    estado_parser = subparsers.add_parser("estado", help="Muestra el estado")
    estado_parser.add_argument("--json", action="store_true")

    args = parser.parse_args()

    if args.orden == "poner":
        if args.stdin:
            valor = sys.stdin.read()
        elif args.valor is None:
            poner_parser.error("Falta el valor (o usa --stdin)")
        else:
            valor = args.valor
        reg = cargar_registro()
        sembrar_theharvester(reg)
        poner_valor(reg, args.herramienta, args.campo, valor)
        guardar_registro(reg)
        print(
            f"✅ {args.herramienta}/{args.campo}: "
            f"definida ({len(valor.strip())} caracteres)"
        )
    elif args.orden == "estado":
        reg = cargar_registro()
        sembrar_theharvester(reg)
        if args.json:
            print(json.dumps(estado_json(reg)))
        else:
            _mostrar_estado(reg)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

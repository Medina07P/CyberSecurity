#!/usr/bin/env python3
# ============================================================
#  API_KEYS.py
#  Registro centralizado de claves de API para el framework.
# ============================================================

import argparse
import configparser
import json
import os
import shutil
import sqlite3
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


def harvester_dirs():
    """Directorios de configuración de theHarvester en orden de preferencia."""
    home = Path.home() / ".theHarvester"
    if "KEYS_HARVESTER_DIRS" in os.environ:
        extras = [Path(p) for p in os.environ["KEYS_HARVESTER_DIRS"].split(":") if p]
        return [home] + extras
    return [
        home,
        Path("/etc/theHarvester"),
        Path("/usr/local/etc/theHarvester"),
    ]


class _ProyeccionIlegible(Exception):
    """La proyección existe pero no se puede parsear."""


class _TheHarvesterAdapter:
    """Adaptador de proyección/ingesta para theHarvester."""

    def _campos(self):
        return _tool_by_name("theharvester")["campos"]

    def _plantilla(self, reg=None, existente=None):
        """Estructura a proyectar: plantilla + campos con valor en registro/proyección."""
        plantilla = _cargar_plantilla_theharvester()
        completa = {
            slot: dict(leaves)
            for slot, leaves in plantilla.items()
            if isinstance(leaves, dict)
        }
        if reg is not None:
            reg_section = reg.get("theharvester", {})
            for campo in self._campos():
                slot, leaf = campo.split(".", 1)
                val_reg, ok_reg = _get_nested(reg_section, campo)
                if ok_reg and val_reg:
                    completa.setdefault(slot, {})[leaf] = None
        if existente is not None:
            for slot, leaves in existente.items():
                if not isinstance(leaves, dict):
                    continue
                for leaf, val in leaves.items():
                    if val:
                        completa.setdefault(slot, {})[leaf] = None
        return completa

    def _destino(self):
        """El destino de escritura es siempre ~/.theHarvester/api-keys.yaml."""
        return harvester_dirs()[0] / "api-keys.yaml"

    def _leer_existente(self, dest):
        if not dest.exists():
            return {}
        try:
            with open(dest) as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            raise _ProyeccionIlegible(
                f"theHarvester: {dest} no es YAML válido: {exc}"
            )
        if not isinstance(data, dict):
            raise _ProyeccionIlegible(
                f"theHarvester: {dest} no contiene un diccionario"
            )
        return data.get("apikeys", {})

    def inicializado(self):
        """True si existe el fichero de claves de theHarvester en ~/.theHarvester."""
        return (harvester_dirs()[0] / "api-keys.yaml").exists()

    def _valores_externos(self, reg):
        """Devuelve los valores no vacíos de la proyección para campos del registro."""
        result = {}
        for d in harvester_dirs():
            candidate = d / "api-keys.yaml"
            if not candidate.exists():
                continue
            try:
                existente = self._leer_existente(candidate)
            except _ProyeccionIlegible:
                continue
            for campo in self._campos():
                slot, leaf = campo.split(".", 1)
                slot_val = existente.get(slot)
                if not isinstance(slot_val, dict):
                    continue
                val_ext = slot_val.get(leaf)
                if isinstance(val_ext, str) and val_ext:
                    result[campo] = val_ext
            return result
        return result

    def proyectar(self, reg, forzar=False):
        """Vuelca el registro a ~/.theHarvester/api-keys.yaml conservando ajenos.

        Si forzar es True y el fichero existente no es legible, se respalda y
        se sobrescribe; esto permite que `poner` recupere un fichero corrupto.
        """
        dest = self._destino()
        try:
            existente = self._leer_existente(dest)
        except _ProyeccionIlegible as exc:
            if not forzar:
                print(f"⚠️  {exc}", file=sys.stderr)
                return False, str(exc)
            print(f"⚠️  {exc}; se sobrescribe con copia de seguridad", file=sys.stderr)
            existente = {}
        plantilla = self._plantilla(reg, existente)
        reg_section = reg.get("theharvester", {})

        contenido = {"apikeys": {}}
        total = 0
        filled = 0
        for slot, leaves in plantilla.items():
            if not isinstance(leaves, dict):
                continue
            contenido["apikeys"][slot] = {}
            for leaf in leaves.keys():
                total += 1
                path = f"{slot}.{leaf}"
                val_reg, ok_reg = _get_nested(reg_section, path)
                if ok_reg and isinstance(val_reg, str) and val_reg:
                    contenido["apikeys"][slot][leaf] = val_reg
                    filled += 1
                else:
                    val_ext, ok_ext = _get_nested(existente, path)
                    if ok_ext and val_ext:
                        contenido["apikeys"][slot][leaf] = val_ext
                    else:
                        contenido["apikeys"][slot][leaf] = ""

        tmp_path = dest.with_name(dest.name + ".tmp")
        try:
            dest.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            if dest.exists():
                respaldo = dest.with_name(dest.name + ".bak")
                shutil.copy2(dest, respaldo)
                respaldo.chmod(0o600)
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                with os.fdopen(fd, "w") as f:
                    yaml.safe_dump(
                        contenido, f, default_flow_style=False,
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
            os.replace(tmp_path, dest)
            dest.chmod(0o600)
        except OSError as exc:
            return False, f"theHarvester: no se pudo escribir {dest}: {exc}"
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

        return True, f"theHarvester: {filled} de {total} campos"

    def ingerir(self, reg):
        """Lee de la proyección valores no vacíos que el registro tenga vacíos."""
        reg_section = reg.get("theharvester", {})
        result = {}
        for campo, val_ext in self._valores_externos(reg).items():
            val_reg, ok_reg = _get_nested(reg_section, campo)
            if ok_reg and val_reg:
                continue
            result[campo] = val_ext
        return result


class _ShodanAdapter:
    """Adaptador de proyección/ingesta para Shodan."""

    def _destino(self):
        return Path.home() / ".shodan" / "api_key"

    def inicializado(self):
        """True si la herramienta ya tiene su fichero o base de datos."""
        return self._destino().exists()

    def _valores_externos(self, reg):
        result = {}
        dest = self._destino()
        if not dest.exists():
            return result
        try:
            val = dest.read_text().strip()
        except OSError:
            return result
        if val:
            result["key"] = val
        return result

    def proyectar(self, reg, forzar=False):
        """Vuelca shodan.key a ~/.shodan/api_key, conservando un valor ajeno."""
        dest = self._destino()
        reg_section = reg.get("shodan", {})
        val_reg, ok_reg = _get_nested(reg_section, "key")
        val = val_reg if ok_reg and isinstance(val_reg, str) else ""

        existente = ""
        if dest.exists():
            try:
                existente = dest.read_text().strip()
            except OSError as exc:
                return False, f"shodan: no se pudo leer {dest}: {exc}"
        if not val and existente:
            val = existente

        tmp_path = dest.with_suffix(".tmp")
        backup = dest.with_name(dest.name + ".bak")
        try:
            dest.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            if dest.exists():
                shutil.copy2(dest, backup)
                backup.chmod(0o600)
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(val)
                    if not val.endswith("\n"):
                        f.write("\n")
                    f.flush()
                    os.fsync(f.fileno())
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            os.replace(tmp_path, dest)
            dest.chmod(0o600)
        except OSError as exc:
            return False, f"shodan: no se pudo escribir {dest}: {exc}"
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

        estado = "puesta" if val else "vacía"
        return True, f"shodan: {estado}"

    def ingerir(self, reg):
        """Lee ~/.shodan/api_key si el registro tiene shodan.key vacío."""
        reg_section = reg.get("shodan", {})
        result = {}
        for campo, val_ext in self._valores_externos(reg).items():
            val_reg, ok_reg = _get_nested(reg_section, campo)
            if ok_reg and val_reg:
                continue
            result[campo] = val_ext
        return result


class _AmassAdapter:
    """Adaptador de proyección/ingesta para amass v5 (datasources.yaml)."""

    def _campos(self):
        return _tool_by_name("amass")["campos"]

    def _destino(self):
        return Path.home() / ".config" / "amass" / "datasources.yaml"

    def _leer_existente(self, dest):
        if not dest.exists():
            return {}
        try:
            with open(dest) as f:
                data = yaml.safe_load(f)
        except (OSError, yaml.YAMLError) as exc:
            raise _ProyeccionIlegible(
                f"amass: no se pudo leer {dest}: {exc}"
            )
        if not isinstance(data, dict):
            raise _ProyeccionIlegible(
                f"amass: {dest} no contiene un diccionario"
            )
        return data

    def _entry_by_name(self, entries, nombre):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            if isinstance(name, str) and name.lower() == nombre.lower():
                return entry
        return None

    def inicializado(self):
        """True si la herramienta ya tiene su fichero o base de datos."""
        return self._destino().exists()

    def _valores_externos(self, reg):
        result = {}
        dest = self._destino()
        if not dest.exists():
            return result
        try:
            data = self._leer_existente(dest)
        except _ProyeccionIlegible:
            return result
        datasources = data.get("datasources")
        if not isinstance(datasources, list):
            return result
        for campo in self._campos():
            source_name, leaf = campo.split(".", 1)
            entry = self._entry_by_name(datasources, source_name)
            if entry is None:
                continue
            creds = entry.get("creds")
            if not isinstance(creds, dict):
                continue
            if leaf not in creds:
                continue
            val_ext = creds.get(leaf)
            if isinstance(val_ext, str) and val_ext:
                result[campo] = val_ext
        return result

    def proyectar(self, reg, forzar=False):
        """Fusiona el registro en ~/.config/amass/datasources.yaml sin alterar el esquema."""
        dest = self._destino()
        if not dest.exists():
            return False, "amass: sin inicializar (ejecuta amass una vez)"
        try:
            data = self._leer_existente(dest)
        except _ProyeccionIlegible as exc:
            print(f"⚠️  {exc}", file=sys.stderr)
            return False, str(exc)

        datasources = data.get("datasources")
        if not isinstance(datasources, list):
            msg = f"amass: {dest} no contiene una lista 'datasources'"
            print(f"⚠️  {msg}", file=sys.stderr)
            return False, msg

        reg_section = reg.get("amass", {})
        total = 0
        filled = 0
        modified = False

        for campo in self._campos():
            total += 1
            source_name, leaf = campo.split(".", 1)
            val_reg, ok_reg = _get_nested(reg_section, campo)
            entry = self._entry_by_name(datasources, source_name)
            if entry is None:
                if ok_reg and isinstance(val_reg, str) and val_reg:
                    print(
                        f"⚠️  amass: la fuente {source_name} no está en datasources.yaml",
                        file=sys.stderr,
                    )
                continue
            creds = entry.get("creds")
            if not isinstance(creds, dict):
                continue
            if leaf not in creds:
                continue
            if ok_reg and isinstance(val_reg, str) and val_reg:
                creds[leaf] = val_reg
                filled += 1
                modified = True
            elif creds.get(leaf):
                # conserva el valor ajeno: ya está ahí
                pass

        if not modified:
            return False, "amass: no se pudo escribir ningún campo"

        tmp_path = dest.with_suffix(".tmp")
        try:
            dest.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                with os.fdopen(fd, "w") as f:
                    yaml.safe_dump(
                        data, f, default_flow_style=False,
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
            os.replace(tmp_path, dest)
            dest.chmod(0o600)
        except OSError as exc:
            return False, f"amass: no se pudo escribir {dest}: {exc}"
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

        return True, f"amass: {filled} de {total} campos"

    def ingerir(self, reg):
        """Lee valores no vacíos de datasources.yaml para campos vacíos en el registro."""
        reg_section = reg.get("amass", {})
        result = {}
        for campo, val_ext in self._valores_externos(reg).items():
            val_reg, ok_reg = _get_nested(reg_section, campo)
            if ok_reg and val_reg:
                continue
            result[campo] = val_ext
        return result


class _H8mailAdapter:
    """Adaptador de proyección/ingesta para h8mail."""

    def _campos(self):
        return _tool_by_name("h8mail")["campos"]

    def _destino(self):
        return Path.home() / ".h8mail_config.ini"

    def inicializado(self):
        """True si la herramienta ya tiene su fichero o base de datos."""
        return self._destino().exists()

    def _valores_externos(self, reg):
        result = {}
        dest = self._destino()
        if not dest.exists():
            return result
        try:
            config = configparser.ConfigParser(interpolation=None)
            with open(dest) as f:
                config.read_file(f)
        except (OSError, configparser.Error):
            return result
        if "h8mail" not in config.sections():
            return result
        for campo in self._campos():
            if config.has_option("h8mail", campo):
                file_val = config.get("h8mail", campo).strip()
                if file_val:
                    result[campo] = file_val
        return result

    def proyectar(self, reg, forzar=False):
        """Vuelca los valores de h8mail a ~/.h8mail_config.ini, conservando ajenos."""
        dest = self._destino()
        reg_section = reg.get("h8mail", {})

        existente = {}
        if dest.exists():
            try:
                config_ex = configparser.ConfigParser(interpolation=None)
                with open(dest) as f:
                    config_ex.read_file(f)
                if "h8mail" in config_ex.sections():
                    for campo in self._campos():
                        if config_ex.has_option("h8mail", campo):
                            existente[campo] = config_ex.get("h8mail", campo).strip()
            except (OSError, configparser.Error) as exc:
                return False, f"h8mail: no se pudo leer {dest}: {exc}"

        config = configparser.ConfigParser(interpolation=None)
        config.add_section("h8mail")
        puestas = 0
        for campo in self._campos():
            val, ok = _get_nested(reg_section, campo)
            if ok and isinstance(val, str) and val:
                config.set("h8mail", campo, val)
                puestas += 1
            elif existente.get(campo):
                config.set("h8mail", campo, existente[campo])
                puestas += 1
            else:
                config.set("h8mail", campo, "")

        tmp_path = dest.with_suffix(".tmp")
        backup = dest.with_name(dest.name + ".bak")
        try:
            if dest.exists():
                shutil.copy2(dest, backup)
                backup.chmod(0o600)
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                with os.fdopen(fd, "w") as f:
                    config.write(f)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            os.replace(tmp_path, dest)
            dest.chmod(0o600)
        except OSError as exc:
            return False, f"h8mail: no se pudo escribir {dest}: {exc}"
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

        if puestas > 0:
            return True, "h8mail: puesta (h8mail necesita -c)"
        return True, "h8mail: vacía"

    def ingerir(self, reg):
        """Lee ~/.h8mail_config.ini para campos vacíos en el registro."""
        reg_section = reg.get("h8mail", {})
        result = {}
        for campo, val_ext in self._valores_externos(reg).items():
            val_reg, ok_reg = _get_nested(reg_section, campo)
            if ok_reg and val_reg:
                continue
            result[campo] = val_ext
        return result


class _ReconNgAdapter:
    """Adaptador de proyección/ingesta para recon-ng (SQLite keys.db)."""

    def _campos(self):
        return _tool_by_name("recon-ng")["campos"]

    def _destino(self):
        return Path.home() / ".recon-ng" / "keys.db"

    def _leer_existente(self, conn):
        rows = {}
        try:
            for name, value in conn.execute("SELECT name, value FROM keys"):
                rows[name] = value
        except sqlite3.Error as exc:
            print(f"⚠️  recon-ng: no se pudo leer la base: {exc}", file=sys.stderr)
        return rows

    def inicializado(self):
        """True si la herramienta ya tiene su fichero o base de datos."""
        return self._destino().exists()

    def _valores_externos(self, reg):
        result = {}
        dest = self._destino()
        if not dest.exists():
            return result
        try:
            conn = sqlite3.connect(str(dest))
            try:
                rows = {
                    name: value
                    for name, value in conn.execute("SELECT name, value FROM keys")
                }
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as exc:
            print(f"⚠️  recon-ng: no se pudo leer {dest}: {exc}", file=sys.stderr)
            return result
        for campo in self._campos():
            val_ext = rows.get(campo)
            if isinstance(val_ext, str) and val_ext:
                result[campo] = val_ext
        return result

    def proyectar(self, reg, forzar=False):
        """Vuelca los valores del registro a ~/.recon-ng/keys.db."""
        dest = self._destino()
        if not dest.exists():
            return False, "recon-ng: sin inicializar"
        reg_section = reg.get("recon-ng", {})
        try:
            conn = sqlite3.connect(str(dest))
            try:
                existente = self._leer_existente(conn)
                total = 0
                filled = 0
                for campo in self._campos():
                    total += 1
                    val_reg, ok_reg = _get_nested(reg_section, campo)
                    if ok_reg and isinstance(val_reg, str) and val_reg:
                        nuevo = val_reg
                    elif existente.get(campo):
                        nuevo = existente[campo]
                    else:
                        continue
                    conn.execute(
                        "INSERT OR REPLACE INTO keys (name, value) VALUES (?, ?)",
                        (campo, nuevo),
                    )
                    filled += 1
                conn.commit()
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as exc:
            return False, f"recon-ng: no se pudo escribir {dest}: {exc}"
        return True, f"recon-ng: {filled} de {total} campos"

    def ingerir(self, reg):
        """Lee de ~/.recon-ng/keys.db los valores no vacíos que el registro tenga vacíos."""
        reg_section = reg.get("recon-ng", {})
        result = {}
        for campo, val_ext in self._valores_externos(reg).items():
            val_reg, ok_reg = _get_nested(reg_section, campo)
            if ok_reg and val_reg:
                continue
            result[campo] = val_ext
        return result


class _SpiderfootAdapter:
    """Adaptador de proyección/ingesta para SpiderFoot (SQLite spiderfoot.db)."""

    def _campos(self):
        return _tool_by_name("spiderfoot")["campos"]

    def _destino(self):
        return Path.home() / ".spiderfoot" / "spiderfoot.db"

    def _leer_existente(self, conn):
        rows = {}
        try:
            for scope, opt, val in conn.execute(
                "SELECT scope, opt, val FROM tbl_config"
            ):
                rows[f"{scope}.{opt}"] = val
        except sqlite3.Error as exc:
            print(f"⚠️  spiderfoot: no se pudo leer la base: {exc}", file=sys.stderr)
        return rows

    def inicializado(self):
        """True si la herramienta ya tiene su fichero o base de datos."""
        return self._destino().exists()

    def _valores_externos(self, reg):
        result = {}
        dest = self._destino()
        if not dest.exists():
            return result
        try:
            conn = sqlite3.connect(str(dest))
            try:
                rows = {
                    f"{scope}.{opt}": val
                    for scope, opt, val in conn.execute(
                        "SELECT scope, opt, val FROM tbl_config"
                    )
                }
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as exc:
            print(f"⚠️  spiderfoot: no se pudo leer {dest}: {exc}", file=sys.stderr)
            return result
        for campo in self._campos():
            val_ext = rows.get(campo)
            if isinstance(val_ext, str) and val_ext:
                result[campo] = val_ext
        return result

    def proyectar(self, reg, forzar=False):
        """Vuelca los valores del registro a ~/.spiderfoot/spiderfoot.db."""
        dest = self._destino()
        if not dest.exists():
            return False, "spiderfoot: sin inicializar"
        reg_section = reg.get("spiderfoot", {})
        try:
            conn = sqlite3.connect(str(dest))
            try:
                existente = self._leer_existente(conn)
                total = 0
                filled = 0
                for campo in self._campos():
                    total += 1
                    val_reg, ok_reg = _get_nested(reg_section, campo)
                    if ok_reg and isinstance(val_reg, str) and val_reg:
                        nuevo = val_reg
                    elif existente.get(campo):
                        nuevo = existente[campo]
                    else:
                        continue
                    scope, opt = campo.rsplit(".", 1)
                    conn.execute(
                        "REPLACE INTO tbl_config (scope, opt, val) VALUES (?, ?, ?)",
                        (scope, opt, nuevo),
                    )
                    filled += 1
                conn.commit()
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as exc:
            return False, f"spiderfoot: no se pudo escribir {dest}: {exc}"
        return True, f"spiderfoot: {filled} de {total} campos"

    def ingerir(self, reg):
        """Lee de ~/.spiderfoot/spiderfoot.db los valores no vacíos que el registro tenga vacíos."""
        reg_section = reg.get("spiderfoot", {})
        result = {}
        for campo, val_ext in self._valores_externos(reg).items():
            val_reg, ok_reg = _get_nested(reg_section, campo)
            if ok_reg and val_reg:
                continue
            result[campo] = val_ext
        return result


def proyectar(herramienta, reg, forzar=False):
    """Proyecta el registro al fichero de configuración de una herramienta."""
    tool = _tool_by_name(herramienta)
    if tool is None or "adaptador" not in tool:
        return False, f"{herramienta}: sin adaptador"
    return tool["adaptador"].proyectar(reg, forzar=forzar)


def ingerir(herramienta):
    """Trae valores desde el fichero de configuración de una herramienta."""
    tool = _tool_by_name(herramienta)
    if tool is None or "adaptador" not in tool:
        return {}
    reg = cargar_registro()
    sembrar_theharvester(reg)
    return tool["adaptador"].ingerir(reg)


def _construir_herramientas():
    """Construye la tabla de herramientas indexada por nombre."""
    ht_plantilla = _cargar_plantilla_theharvester()
    ht_campos_template = _campos_theharvester(ht_plantilla)
    # La plantilla da la estructura real; los campos por defecto aseguran que
    # todos los huecos conocidos sigan siendo validables y proyectables.
    ht_campos = ht_campos_template + [
        c for c in _DEFAULT_HARVESTER_CAMPOS if c not in ht_campos_template
    ]
    return {
        "theharvester": {
            "nombre": "theharvester",
            "etiqueta": "theHarvester",
            "campos": ht_campos,
            "adaptador": _TheHarvesterAdapter(),
        },
        "shodan": {
            "nombre": "shodan",
            "etiqueta": "Shodan",
            "campos": ["key"],
            "adaptador": _ShodanAdapter(),
        },
        "h8mail": {
            "nombre": "h8mail",
            "etiqueta": "h8mail",
            "campos": [
                "hunterio", "snusbase_token", "weleakinfo_priv", "weleakinfo_pub",
                "hibp", "leak-lookup_pub", "leak-lookup_priv", "emailrep",
                "dehashed_email", "dehashed_key", "intelx_key", "intelx_maxfile",
                "breachdirectory_user", "breachdirectory_pass",
            ],
            "adaptador": _H8mailAdapter(),
        },
        "amass": {
            "nombre": "amass",
            "etiqueta": "Amass",
            "campos": [
                "shodan.key", "censys.id", "censys.secret", "securitytrails.key",
                "virustotal.key", "urlscan.key",
            ],
            "adaptador": _AmassAdapter(),
        },
        "recon-ng": {
            "nombre": "recon-ng",
            "etiqueta": "recon-ng",
            "campos": [
                "shodan_api", "censys_api_id", "censys_api_secret",
                "securitytrails_api", "virustotal_api", "hunter_api", "github_api",
            ],
            "adaptador": _ReconNgAdapter(),
        },
        "spiderfoot": {
            "nombre": "spiderfoot",
            "etiqueta": "SpiderFoot",
            "campos": [
                "sfp_shodan.api_key", "sfp_censys.api_key",
                "sfp_securitytrails.api_key", "sfp_virustotal.api_key",
                "sfp_hunter.api_key", "sfp_urlscan.api_key",
            ],
            "adaptador": _SpiderfootAdapter(),
        },
    }


HERRAMIENTAS = _construir_herramientas()


def _tool_by_name(nombre):
    return HERRAMIENTAS.get(nombre)


def _binario_herramienta(nombre):
    """Nombre del ejecutable esperado en PATH para una herramienta."""
    return {
        "theharvester": "theHarvester",
        "shodan": "shodan",
        "h8mail": "h8mail",
        "amass": "amass",
        "recon-ng": "recon-ng",
        "spiderfoot": "spiderfoot",
    }.get(nombre)


def _hay_binario(nombre):
    """True si el ejecutable de la herramienta está disponible en PATH."""
    nombre_bin = _binario_herramienta(nombre)
    if not nombre_bin:
        return False
    if shutil.which(nombre_bin):
        return True
    # Fallback para theHarvester, que a veces se instala en minúsculas.
    if nombre == "theharvester" and shutil.which("theharvester"):
        return True
    return False


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


def _valor_registro(seccion, campo):
    """Valor del registro para un campo, como cadena vacía si no lo hay."""
    val, ok = _get_nested(seccion, campo)
    return val if ok and isinstance(val, str) else ""


def _diverge(tool, seccion, valores_ext):
    """True si la herramienta guarda un valor no vacío que el registro no explica.

    Un hueco vacío en la herramienta no es divergencia: solo cuenta lo que el
    registro no puede justificar (valor distinto del registrado o desconocido).
    """
    for campo in tool["campos"]:
        val_ext = valores_ext.get(campo)
        if val_ext and val_ext != _valor_registro(seccion, campo):
            return True
    return False


def _tiene_valores(reg, nombre):
    """True si el registro guarda algún valor para esa herramienta."""
    seccion = reg.get(nombre, {})
    return any(
        _valor_registro(seccion, campo)
        for campo in _tool_by_name(nombre)["campos"]
    )


def estado_herramienta(nombre, reg):
    """Devuelve el estado consolidado de una herramienta sin revelar secretos."""
    tool = _tool_by_name(nombre)
    seccion = reg.get(nombre, {})
    campos_json = []
    puestas = 0
    for campo in tool["campos"]:
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

    hay_binario = _hay_binario(nombre)
    inicializado = tool["adaptador"].inicializado()
    valores_ext = tool["adaptador"]._valores_externos(reg)

    if not hay_binario and not inicializado:
        estado = "no instalada"
    elif _diverge(tool, seccion, valores_ext):
        estado = "diverge"
    elif not inicializado:
        estado = "sin inicializar"
    elif puestas == 0:
        estado = "vacía"
    elif nombre == "h8mail":
        estado = "puesta (h8mail necesita -c)"
    else:
        estado = "puesta (sin verificar)"

    return {
        "nombre": nombre,
        "etiqueta": tool["etiqueta"],
        "puestas": puestas,
        "total": len(tool["campos"]),
        "estado": estado,
        "campos": campos_json,
    }


def estado_json(reg):
    """Devuelve el estado del registro sin escribir ni revelar secretos."""
    return {
        "herramientas": [
            estado_herramienta(nombre, reg)
            for nombre in HERRAMIENTAS.keys()
        ]
    }


def _mostrar_estado(reg):
    print("\n🔐 ESTADO DE CLAVES DE API")
    print("=" * 60)
    herramientas = estado_json(reg)["herramientas"]
    ancho = max(len(h["etiqueta"]) for h in herramientas)
    for h in herramientas:
        print(
            f"  {h['etiqueta']:<{ancho}}  "
            f"{h['puestas']:>2}/{h['total']:<2}  {h['estado']}"
        )


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
    estado_parser.add_argument("--faltan", metavar="HERRAMIENTA")

    sinc_parser = subparsers.add_parser(
        "sincronizar", help="Vuelca el registro a los ficheros de herramienta"
    )
    sinc_parser.add_argument("herramienta", nargs="?")

    imp_parser = subparsers.add_parser(
        "importar", help="Trae valores desde los ficheros de herramienta"
    )
    imp_parser.add_argument("herramienta")

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
        ok, msg = proyectar(args.herramienta, reg, forzar=True)
        if not ok:
            print(f"⚠️  {msg}", file=sys.stderr)
            sys.exit(3)
        print(f"✅ {msg}")
    elif args.orden == "estado":
        reg = cargar_registro()
        sembrar_theharvester(reg)
        if args.faltan:
            tool = _tool_by_name(args.faltan)
            if tool is None:
                print(f"❌ Herramienta desconocida: {args.faltan}", file=sys.stderr)
                sys.exit(2)
            info = estado_herramienta(args.faltan, reg)
            faltan = info["total"] - info["puestas"]
            if faltan > 0:
                print(f"⚠️  {args.faltan}: faltan {faltan} de {info['total']} campos")
                sys.exit(1)
            print(f"✅ {args.faltan}: todos los campos están definidos")
            sys.exit(0)
        if args.json:
            print(json.dumps(estado_json(reg)))
        else:
            _mostrar_estado(reg)
    elif args.orden == "sincronizar":
        reg = cargar_registro()
        sembrar_theharvester(reg)
        herramientas = (
            [args.herramienta]
            if args.herramienta
            else list(HERRAMIENTAS.keys())
        )
        exit_code = 0
        for nombre in herramientas:
            tool = _tool_by_name(nombre)
            if not _tiene_valores(reg, nombre) and not tool["adaptador"].inicializado():
                print(f"⬜ {tool['etiqueta']}: sin valores y sin fichero, no se crea")
                continue
            ok, msg = proyectar(nombre, reg)
            if not ok:
                print(f"⚠️  {msg}", file=sys.stderr)
                exit_code = 3
            else:
                print(f"✅ {msg}")
        sys.exit(exit_code)
    elif args.orden == "importar":
        if not args.herramienta:
            imp_parser.error("Falta la herramienta")
        vals = ingerir(args.herramienta)
        if vals:
            reg = cargar_registro()
            sembrar_theharvester(reg)
            for path, val in vals.items():
                _set_nested(reg[args.herramienta], path, val)
            guardar_registro(reg)
        print(f"✅ {args.herramienta}: importados {len(vals)} campos")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

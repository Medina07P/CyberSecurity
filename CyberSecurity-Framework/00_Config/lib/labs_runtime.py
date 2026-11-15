#!/usr/bin/env python3
"""Exclusive lab initialization runtime."""
from __future__ import annotations

import errno
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

KIND_ROOTS = {
    "htb": ("hackthebox", "machines"),
    "thm": ("tryhackme", "rooms"),
    "ad": ("active_directory", "machines"),
    "web": ("web_apps", "machines"),
    "cloud": ("cloud", "machines"),
}

SECTIONS = {
    "htb": ("IP", "Puertos abiertos", "Servicios", "Hallazgos", "Explotación", "Post-explotación", "Flags"),
    "thm": ("IP", "Puertos", "Hallazgos", "Explotación", "Flags"),
    "ad": ("Controladores de Dominio", "Usuarios", "Grupos", "Hallazgos", "Ataques", "Flags"),
    "web": ("URL", "Tecnologías", "Hallazgos", "Explotación", "Flags"),
    "cloud": ("Proveedor", "Recursos", "Credenciales", "Hallazgos", "Explotación"),
}

TITLES = {
    "htb": "HTB",
    "thm": "THM",
    "ad": "AD",
    "web": "Web",
    "cloud": "Cloud",
}

SUBDIRS = ("recon", "exploits", "loot", "notes")


@dataclass(frozen=True)
class LabResult:
    path: Path
    created_notes: bool


def validate_name(name):
    if not isinstance(name, str):
        raise ValueError("invalid lab name")
    if name == "" or name == "." or name == "..":
        raise ValueError("invalid lab name")
    if "/" in name or "\\" in name:
        raise ValueError("invalid lab name: path separator")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
        raise ValueError("invalid lab name: control character")
    if os.sep in name or (os.altsep is not None and os.altsep in name):
        raise ValueError("invalid lab name: path separator")
    return name


def _mkdir_nofollow(path, mode):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        try:
            os.mkdir(path, mode)
            os.chmod(path, mode)
            return True
        except FileExistsError:
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise OSError(errno.EEXIST, "not a directory", str(path))
            return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise OSError(errno.EEXIST, "not a directory", str(path))
    return False


def _content(kind, name):
    title = TITLES[kind]
    lines = []
    lines.append("# {} - {}".format(title, name))
    lines.append("")
    lines.append("VPN: no comprobada")
    lines.append("")
    for section in SECTIONS[kind]:
        lines.append("## " + section)
        if section == "IP" and kind in ("htb", "thm"):
            lines.append("no comprobada")
        lines.append("```")
        lines.append("```")
        lines.append("")
    text = "\n".join(lines)
    if kind == "htb":
        text = text.replace("## Flags\n```\n```\n", "## Flags\n- user:\n- root:\n", 1)
    return text


def initialize_lab(kind, name, output_root=None):
    if kind not in KIND_ROOTS:
        raise ValueError("invalid lab kind")
    validate_name(name)

    if output_root is None:
        framework = Path(__file__).resolve().parents[2]
        category, folder = KIND_ROOTS[kind]
        root = framework / "13_Labs" / category / folder
    else:
        root = Path(output_root)
    root = root.absolute()

    target = root / name

    try:
        _mkdir_nofollow(root, 0o700)
        _mkdir_nofollow(target, 0o700)
        for sd in SUBDIRS:
            _mkdir_nofollow(target / sd, 0o700)
    except Exception:
        raise

    notes_dir = target / "notes"
    readme = notes_dir / "README.md"

    try:
        st = os.lstat(readme)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EEXIST, "not a regular file", str(readme))
    except FileNotFoundError:
        pass

    content = _content(kind, name)

    created_notes = False
    try:
        fd = os.open(str(readme), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created_readme = True
        os.fchmod(fd, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
            created_notes = True
        except BaseException:
            try:
                os.unlink(str(readme))
            except OSError:
                pass
            raise
    except FileExistsError:
        created_notes = False

    return LabResult(path=target, created_notes=created_notes)


def _usage():
    return (
        "Uso: labs_runtime.py <kind> <name> [--root DIR]\n"
        "Tipos: htb, thm, ad, web, cloud\n"
        "Ejemplo: labs_runtime.py htb Blue"
    )


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        sys.stderr.write(_usage() + "\n")
        return 2
    kind = argv[0]
    name = argv[1]
    output_root = None
    i = 2
    while i < len(argv):
        if argv[i] == "--root":
            if i + 1 >= len(argv):
                sys.stderr.write(_usage() + "\n")
                return 2
            output_root = argv[i + 1]
            i += 2
        else:
            sys.stderr.write(_usage() + "\n")
            return 2
    if kind not in KIND_ROOTS:
        sys.stderr.write("Tipo no válido: {}\n".format(kind))
        sys.stderr.write(_usage() + "\n")
        return 2
    try:
        validate_name(name)
    except ValueError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 2
    try:
        initialize_lab(kind, name, output_root)
    except ValueError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 2
    except Exception as exc:
        sys.stderr.write("error: {}\n".format(exc))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

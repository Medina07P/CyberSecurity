#!/usr/bin/env python3
"""Exclusive lab initialization runtime."""
from __future__ import annotations

import errno
import os
import stat
import sys
from contextlib import ExitStack
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


def _open_directory_at(parent_fd, name, create=False):
    """Pin a directory without following links or changing existing modes."""
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                   dir_fd=parent_fd)


def _open_root(root):
    """Check every ancestor; only the explicitly selected root may be created."""
    fd = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for index, component in enumerate(root.parts[1:], start=1):
            child = _open_directory_at(fd, component, create=index == len(root.parts) - 1)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _reuse_notes(notes_fd):
    # Linux O_PATH pins metadata without reading a prior note (or requiring its
    # read permission). O_NOFOLLOW pins a link itself, whose type is then refused.
    fd = os.open('README.md', os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=notes_fd)
    try:
        opened = os.fstat(fd)
        current = os.stat('README.md', dir_fd=notes_fd, follow_symlinks=False)
        if (not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(current.st_mode) or
                (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)):
            raise OSError(errno.EEXIST, 'not the same regular notes file')
    finally:
        os.close(fd)


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
        framework = Path(__file__).absolute().parents[2]
        category, folder = KIND_ROOTS[kind]
        root = framework / "13_Labs" / category / folder
    else:
        root = Path(output_root)
    root = root.absolute()

    target = root / name

    with ExitStack() as descriptors:
        root_fd = _open_root(root)
        descriptors.callback(os.close, root_fd)
        target_fd = _open_directory_at(root_fd, name, create=True)
        descriptors.callback(os.close, target_fd)
        for subdirectory in SUBDIRS:
            child_fd = _open_directory_at(target_fd, subdirectory, create=True)
            descriptors.callback(os.close, child_fd)
            if subdirectory == 'notes':
                notes_fd = child_fd

        try:
            fd = os.open('README.md', os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=notes_fd)
        except FileExistsError:
            _reuse_notes(notes_fd)
            return LabResult(path=target, created_notes=False)

        # The exclusive descriptor is ours. Errors preserve the partial file;
        # no pathname cleanup may delete a concurrently replaced object.
        try:
            os.fchmod(fd, 0o600)
            created = os.fstat(fd)
            stream = os.fdopen(fd, 'w', encoding='utf-8')
        except BaseException:
            os.close(fd)
            raise
        with stream:
            stream.write(_content(kind, name))
        current = os.stat('README.md', dir_fd=notes_fd, follow_symlinks=False)
        if (not stat.S_ISREG(current.st_mode) or
                (created.st_dev, created.st_ino) != (current.st_dev, current.st_ino)):
            raise OSError(errno.EEXIST, 'notes file changed during initialization')

    return LabResult(path=target, created_notes=True)


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

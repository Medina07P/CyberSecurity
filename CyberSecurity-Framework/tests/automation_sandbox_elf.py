"""Bounded ELF64 reader/resolver. Reads bytes only; no loader/ldd/subprocess.

NOT RUN before collective static gate. Unsupported metadata fails closed.
"""
from collections import deque
from dataclasses import dataclass
from pathlib import Path
import struct

from automation_sandbox_prepare import IsolationBlocked, RuntimeFile, read_regular


LIBDIR = Path('/usr/lib/x86_64-linux-gnu')
LOADER = '/lib64/ld-linux-x86-64.so.2'
MAX_ELF = 32 * 1024 * 1024
MAX_DEPENDENCIES = 1024
MAX_DEPTH = 64


@dataclass(frozen=True)
class ElfInfo:
    interpreter: str | None
    needed: tuple[str, ...]
    rpaths: tuple[str, ...]


def _slice(data, offset, size):
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise IsolationBlocked('ELF offset/size outside file')
    return data[offset:offset + size]


def _cstring(data, offset):
    if offset < 0 or offset >= len(data):
        raise IsolationBlocked('ELF string offset outside string table')
    end = data.find(b'\0', offset)
    if end < 0 or end - offset > 4096:
        raise IsolationBlocked('ELF string unterminated/too long')
    try:
        return data[offset:end].decode('ascii')
    except UnicodeError as exc:
        raise IsolationBlocked('Non-ASCII ELF string') from exc


def _rpaths(value, path):
    result = []
    for item in value.split(':'):
        expanded = item
        if item.startswith('$ORIGIN'):
            # No relative traversal, substitutions, or host-specific search.
            if path.parent != LIBDIR or item != '$ORIGIN':
                raise IsolationBlocked('Uncontained $ORIGIN')
            expanded = str(LIBDIR)
        if expanded != str(LIBDIR):
            raise IsolationBlocked('Unapproved ELF search path')
        result.append(item)
    return result


def read_elf(path: Path) -> ElfInfo:
    path = Path(path)
    data = read_regular(path, MAX_ELF)
    return _parse_elf(data, path)


def _read_staged_elf(path, destination):
    # Parse copied bytes using their logical sandbox directory for $ORIGIN.
    return _parse_elf(read_regular(path, MAX_ELF), Path(destination))


def _parse_elf(data, path):
    header = _slice(data, 0, 64)
    if (header[:7] != b'\x7fELF\x02\x01\x01' or
            header[7] not in (0, 3) or header[8] != 0):
        raise IsolationBlocked('Only ELF64 little-endian Linux is supported')
    (kind, machine, version, _entry, phoff, _shoff, _flags, ehsize,
     phentsize, phnum, _shentsize, _shnum, _shstrndx) = struct.unpack('<HHIQQQIHHHHHH', header[16:])
    if (kind not in (2, 3) or machine != 62 or version != 1 or
            ehsize != 64 or phentsize != 56 or not 0 < phnum <= 4096):
        raise IsolationBlocked('Unsupported ELF header')
    table = _slice(data, phoff, phnum * phentsize)
    loads, dynamic, dynamic_location, interpreter = [], None, None, None
    for index in range(phnum):
        ptype, _pflags, offset, address, _physical, filesz, memsz, _align = struct.unpack(
            '<IIQQQQQQ', table[index * 56:(index + 1) * 56])
        segment = _slice(data, offset, filesz)
        if ptype == 1:
            if filesz > memsz or address + memsz >= 1 << 64:
                raise IsolationBlocked('Invalid ELF load segment')
            loads.append((offset, address, filesz))
        elif ptype == 2:
            if (dynamic is not None or filesz > memsz or filesz % 16 or
                    filesz // 16 > 65536):
                raise IsolationBlocked('Invalid/duplicate ELF dynamic segment')
            dynamic = segment
            dynamic_location = (offset, address, filesz)
        elif ptype == 3:
            if interpreter is not None or not segment or segment[-1:] != b'\0':
                raise IsolationBlocked('Invalid/duplicate ELF interpreter')
            interpreter = _cstring(segment, 0)
            if interpreter != LOADER or len(segment) != len(interpreter) + 1:
                raise IsolationBlocked('Unapproved ELF interpreter')
    if not loads:
        raise IsolationBlocked('ELF has no load segment')
    if dynamic is None:
        return ElfInfo(interpreter, (), ())
    offset, address, length = dynamic_location
    mappings = [start_offset + address - start
                for start_offset, start, size in loads
                if start <= address and address - start <= size and
                length <= size - (address - start)]
    if mappings != [offset]:
        raise IsolationBlocked('ELF dynamic segment not uniquely mapped to its file bytes')
    needed_offsets, search_offsets, single = [], [], {}
    for cursor in range(0, len(dynamic), 16):
        tag, value = struct.unpack('<qQ', dynamic[cursor:cursor + 16])
        if tag == 0:
            break
        if tag == 1:
            needed_offsets.append(value)
            if len(needed_offsets) > MAX_DEPENDENCIES:
                raise IsolationBlocked('Too many ELF dependencies')
        elif tag in (5, 10, 15, 29):
            if tag in single:
                raise IsolationBlocked('Duplicate ELF singleton tag')
            single[tag] = value
            if tag in (15, 29):
                search_offsets.append(value)
        elif tag in (0x7fffffff, 0x7ffffffd, 0x6ffffefa, 0x6ffffefb, 0x6ffffefc):
            # DT_FILTER/AUXILIARY/AUDIT/DEPAUDIT load code outside DT_NEEDED.
            raise IsolationBlocked('Unsupported ELF implicit dependency tag')
    else:
        raise IsolationBlocked('ELF dynamic segment lacks terminator')
    if 5 not in single or 10 not in single or not 0 < single[10] <= MAX_ELF:
        raise IsolationBlocked('ELF dynamic string table missing/invalid')
    address, length = single[5], single[10]
    candidates = [(offset + address - start) for offset, start, size in loads
                  if start <= address and address - start <= size and
                  length <= size - (address - start)]
    if len(candidates) != 1:
        raise IsolationBlocked('ELF string table not uniquely file-backed')
    strings = _slice(data, candidates[0], length)
    needed = []
    for offset in needed_offsets:
        name = _cstring(strings, offset)
        if (not name or '/' in name or '\\' in name or name in ('.', '..') or
                len(name) > 255 or any(ord(c) < 33 or ord(c) > 126 for c in name)):
            raise IsolationBlocked('Invalid DT_NEEDED basename')
        if name in needed:
            raise IsolationBlocked('Duplicate DT_NEEDED')
        needed.append(name)
    paths = []
    for offset in search_offsets:
        paths.extend(_rpaths(_cstring(strings, offset), path))
    return ElfInfo(interpreter, tuple(needed), tuple(paths))


def _library(name):
    try:
        path = (LIBDIR / name).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise IsolationBlocked('Missing ELF dependency: ' + name) from exc
    if path.parent != LIBDIR:
        raise IsolationBlocked('ELF dependency alias escapes library directory')
    return path


def resolve_runtime(entries: tuple[RuntimeFile, ...]) -> tuple[RuntimeFile, ...]:
    by_destination = {}
    pending = deque()
    for entry in entries:
        destination = Path(entry.destination)
        if (not destination.is_absolute() or '..' in destination.parts or
                str(destination) != entry.destination or entry.destination in by_destination or
                entry.category not in ('elf', 'python', 'yaml')):
            raise IsolationBlocked('Invalid/duplicate runtime destination')
        by_destination[entry.destination] = entry
        if entry.category == 'elf':
            pending.append((entry, 0))
    elf_destinations = len(pending)
    if elf_destinations > MAX_DEPENDENCIES:
        raise IsolationBlocked('Initial ELF inventory exceeds dependency bound')
    visited = set()
    while pending:
        entry, depth = pending.popleft()
        if entry.source in visited:
            continue
        if depth > MAX_DEPTH or len(visited) >= MAX_DEPENDENCIES:
            raise IsolationBlocked('ELF transitive closure bound exceeded')
        visited.add(entry.source)
        info = read_elf(entry.source)
        dependencies = [(name, str(LIBDIR / name)) for name in info.needed]
        if info.interpreter:
            dependencies.append((None, info.interpreter))
        for name, destination in dependencies:
            if name is None:
                try:
                    source = Path(LOADER).resolve(strict=True)
                except (OSError, RuntimeError) as exc:
                    raise IsolationBlocked('Missing approved loader') from exc
                if source.parent != LIBDIR or source.name != 'ld-linux-x86-64.so.2':
                    raise IsolationBlocked('Unexpected canonical loader')
            else:
                source = _library(name)
            dependency = RuntimeFile(source, destination, 'elf')
            old = by_destination.get(destination)
            if old is not None:
                if old != dependency:
                    raise IsolationBlocked('Conflicting runtime destination')
                continue
            elf_destinations += 1
            if elf_destinations > MAX_DEPENDENCIES:
                raise IsolationBlocked('ELF destination closure bound exceeded')
            by_destination[destination] = dependency
            pending.append((dependency, depth + 1))
    return tuple(by_destination[name] for name in sorted(by_destination))

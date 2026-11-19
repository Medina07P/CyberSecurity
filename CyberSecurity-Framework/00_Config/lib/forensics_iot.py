#!/usr/bin/env python3
"""Soporte 08 para soportes portátiles: triaje, VirusTotal, guardas y limpieza.

Este módulo NO es un ejecutor genérico ni una cadena de custodia. No abre
originales fuera de las copias privadas que le entrega el runtime, no imprime
cuerpos de archivos y nunca escribe la clave de API.

Subcomandos:
  mkdir        crea un directorio privado (700) sin seguir enlaces.
  reserve      reserva un fichero nuevo (600, O_EXCL, O_NOFOLLOW).
  triage       inventario + hashes + familia + metadatos opcionales.
  vt           consulta VirusTotal v3 solo con hashes.
  device-guard comprueba que un dispositivo es seguro para leer/borrar.
  zero-check   verifica ceros reales en el inicio y el final del soporte.
  fs-check     verifica la firma de un sistema de archivos recién creado.
  receipt      escribe el recibo privado de una esterilización.
  report-path  resuelve el informe de triaje de un run ya validado.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = 1
CHUNK = 1024 * 1024
MIB = 1024 * 1024
VT_BASE = 'https://www.virustotal.com/api/v3'
LOOPBACK = {'127.0.0.1', 'localhost', '::1'}
VT_KEY = 'VT_API_KEY'

# Familias estables para el informe; no son veredictos forenses.
FAMILIES = ('imagen', 'video', 'audio', 'documento', 'comprimido',
            'ejecutable', 'base_de_datos', 'texto', 'fuente', 'desconocido')

# (firma, familia, etiqueta). Se comprueba en orden; la primera coincidencia gana.
SIGNATURES = (
    (b'\xff\xd8\xff', 'imagen', 'JPEG'),
    (b'\x89PNG\r\n\x1a\n', 'imagen', 'PNG'),
    (b'GIF87a', 'imagen', 'GIF'),
    (b'GIF89a', 'imagen', 'GIF'),
    (b'II*\x00', 'imagen', 'TIFF'),
    (b'MM\x00*', 'imagen', 'TIFF'),
    (b'BM', 'imagen', 'BMP'),
    (b'\x00\x00\x01\x00', 'imagen', 'ICO'),
    (b'%PDF-', 'documento', 'PDF'),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'documento', 'OLE2'),
    (b'{\\rtf', 'documento', 'RTF'),
    (b'%!PS', 'documento', 'PostScript'),
    (b'PK\x03\x04', 'comprimido', 'ZIP'),
    (b'Rar!\x1a\x07', 'comprimido', 'RAR'),
    (b'7z\xbc\xaf\x27\x1c', 'comprimido', '7Z'),
    (b'\x1f\x8b', 'comprimido', 'GZIP'),
    (b'BZh', 'comprimido', 'BZIP2'),
    (b'\xfd7zXZ\x00', 'comprimido', 'XZ'),
    (b'\x7fELF', 'ejecutable', 'ELF'),
    (b'MZ', 'ejecutable', 'PE'),
    (b'SQLite format 3\x00', 'base_de_datos', 'SQLITE'),
    (b'fLaC', 'audio', 'FLAC'),
    (b'OggS', 'audio', 'OGG'),
    (b'ID3', 'audio', 'MP3'),
    (b'\x00\x00\x00\x18ftyp', 'video', 'MP4'),
    (b'\x00\x00\x00\x20ftyp', 'video', 'MP4'),
    (b'\x1aE\xdf\xa3', 'video', 'MATROSKA'),
    (b'wOFF', 'fuente', 'WOFF'),
    (b'OTTO', 'fuente', 'OTF'),
    (b'\x00\x01\x00\x00\x00', 'fuente', 'TTF'),
    (b'{\n', 'texto', 'JSON?'),
    (b'<?xml', 'texto', 'XML'),
    (b'<!DOCTYPE html', 'texto', 'HTML'),
    (b'<html', 'texto', 'HTML'),
)

# Extensiones frecuentes en recuperaciones de PhotoRec/Foremost.
EXTENSIONS = {
    'imagen': ('jpg', 'jpeg', 'png', 'gif', 'bmp', 'tif', 'tiff', 'webp',
               'heic', 'ico', 'raw', 'cr2', 'nef', 'dng'),
    'video': ('mp4', 'mov', 'avi', 'mkv', 'webm', 'flv', 'wmv', 'mpg', 'mpeg', '3gp'),
    'audio': ('mp3', 'wav', 'flac', 'ogg', 'm4a', 'aac', 'wma', 'amr', 'opus'),
    'documento': ('pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt',
                  'ods', 'odp', 'rtf', 'txt', 'csv', 'md', 'eml', 'msg', 'ps'),
    'comprimido': ('zip', 'rar', '7z', 'gz', 'bz2', 'xz', 'tar', 'jar', 'iso', 'cab'),
    'ejecutable': ('exe', 'dll', 'elf', 'so', 'bin', 'sh', 'py', 'pl', 'js', 'php', 'bat', 'msi', 'apk'),
    'base_de_datos': ('db', 'sqlite', 'sqlite3', 'mdb', 'accdb', 'dbf'),
    'fuente': ('ttf', 'otf', 'woff', 'woff2'),
}
EXTENSION_FAMILY = {ext: family for family, exts in EXTENSIONS.items() for ext in exts}


class Unsafe(ValueError):
    """Precondición de seguridad incumplida."""


def _fail(message):
    print('NO_EVALUABLE: ' + message, file=sys.stderr)
    raise SystemExit(2)


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _clean_text(value, limit=200):
    if not isinstance(value, str):
        return ''
    value = ''.join(c for c in value if ord(c) >= 32 and ord(c) != 127)
    return value[:limit]


def _path(value):
    result = Path(os.path.abspath(value))
    if any(ord(c) < 32 or ord(c) == 127 for c in str(result)):
        raise Unsafe('ruta con caracteres de control')
    for part in (*reversed(result.parents), result):
        if part.is_symlink():
            raise Unsafe('la ruta o un componente es un enlace simbólico')
    return result


def _open_new(path, mode=0o600):
    target = _path(path)
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    except FileExistsError:
        raise Unsafe('el fichero ya existe; no se sobrescribe') from None
    return os.fdopen(fd, 'w', encoding='utf-8', newline='\n')


def _digest(path):
    sha = hashlib.sha256()
    size = 0
    with open(path, 'rb') as stream:
        while True:
            block = stream.read(CHUNK)
            if not block:
                break
            sha.update(block)
            size += len(block)
    return sha.hexdigest(), size


def classify(head, suffix):
    """Firma por bytes; la extensión solo se usa si no hay firma conocida."""
    for signature, family, label in SIGNATURES:
        if head.startswith(signature):
            return family, label
    if head[:4] == b'RIFF' and len(head) >= 12:
        kind = head[8:12]
        if kind == b'WAVE':
            return 'audio', 'WAV'
        if kind == b'AVI ':
            return 'video', 'AVI'
        return 'desconocido', 'RIFF'
    if len(head) >= 262 and head[257:262] == b'ustar':
        return 'comprimido', 'TAR'
    ext = suffix.lower().lstrip('.')
    family = EXTENSION_FAMILY.get(ext)
    if family:
        return family, 'EXTENSION'
    return 'desconocido', 'SIN_FIRMA'


def _exiftool_metadata(path):
    try:
        done = subprocess.run(['exiftool', '-json', '-q', '-q', '-n', '--', str(path)],
                              capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    try:
        rows = json.loads(done.stdout.decode('utf-8', 'replace'))
    except (ValueError, TypeError):
        return None
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        return None
    row = rows[0]
    wanted = {'MIMEType': 'tipo_mime', 'FileType': 'tipo_archivo',
              'Make': 'fabricante', 'Model': 'modelo',
              'DateTimeOriginal': 'fecha_original', 'CreateDate': 'fecha_creacion',
              'Author': 'autor', 'Creator': 'creador', 'Producer': 'productor',
              'PageCount': 'paginas', 'ImageWidth': 'ancho', 'ImageHeight': 'alto'}
    metadata = {}
    for key, label in wanted.items():
        value = row.get(key)
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            text = _clean_text(str(value))
            if text:
                metadata[label] = text
    return metadata or None


def triage(root, json_path, md_path, investigator='', use_exiftool=False, exiftool_limit=200):
    base = _path(root)
    if not base.is_dir():
        raise Unsafe('la raíz de triaje no es un directorio')
    rows = []
    warnings = []
    seen_hashes = {}
    metadata_used = 0
    for current, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames.sort()
        current_path = Path(current)
        for name in dirnames:
            if (current_path / name).is_symlink():
                raise Unsafe('el árbol contiene un enlace simbólico')
        for name in sorted(filenames):
            item = current_path / name
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise Unsafe('el árbol contiene un enlace simbólico')
            if not stat.S_ISREG(info.st_mode):
                raise Unsafe('el árbol contiene un nodo no regular')
            with open(item, 'rb') as stream:
                head = stream.read(512)
            digest, size = _digest(item)
            family, label = classify(head, item.suffix)
            extension = item.suffix[1:].lower() if item.suffix else ''
            row = {'ruta': item.relative_to(base).as_posix(), 'bytes': size,
                   'sha256': digest, 'extension': extension,
                   'familia': family, 'firma': label}
            if use_exiftool and metadata_used < exiftool_limit:
                metadata = _exiftool_metadata(item)
                metadata_used += 1
                if metadata:
                    row['metadatos'] = metadata
            rows.append(row)
            if digest in seen_hashes:
                row['duplicado_de'] = seen_hashes[digest]
            else:
                seen_hashes[digest] = row['ruta']
    if use_exiftool and len(rows) > exiftool_limit:
        warnings.append('Metadatos limitados a %d archivos; el resto solo tiene hash '
                        'y clasificación.' % exiftool_limit)
    summary = {'total': len(rows), 'bytes': sum(r['bytes'] for r in rows),
               'por_familia': {}}
    for row in rows:
        summary['por_familia'][row['familia']] = summary['por_familia'].get(row['familia'], 0) + 1
    report = {'version': VERSION, 'generado_utc': _now(),
              'investigador': _clean_text(investigator, 120),
              'herramienta': 'forensics_iot.triage',
              'archivos': rows, 'resumen': summary, 'advertencias': warnings}
    _write_json(json_path, report)
    _write_markdown(md_path, report)
    return report


def _write_json(path, payload):
    with _open_new(path) as stream:
        json.dump(payload, stream, ensure_ascii=True, sort_keys=True, indent=1)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def _write_markdown(path, report):
    lines = ['# Inventario de archivos recuperados', '',
             '- Generado (UTC): %s' % report['generado_utc'],
             '- Investigador: %s' % (report['investigador'] or 'no indicado'),
             '- Archivos: %d; bytes: %d' % (report['resumen']['total'],
                                            report['resumen']['bytes']),
             '',
             'Un hash y una firma no demuestran autoría, intención ni malware.',
             'Este informe describe una COPIA privada, no el soporte original.', '']
    if report['advertencias']:
        lines.extend('## Advertencias', '')
        lines.extend('- %s' % item for item in report['advertencias'])
        lines.append('')
    lines.extend(['## Familias', '', '| Familia | Archivos |', '|---|---|'])
    for family in sorted(report['resumen']['por_familia']):
        lines.append('| %s | %d |' % (family, report['resumen']['por_familia'][family]))
    lines.extend(['', '## Archivos', '',
                  '| Ruta | Bytes | SHA-256 | Ext | Familia | Firma |',
                  '|---|---|---|---|---|---|'])
    for row in report['archivos']:
        lines.append('| %s | %d | `%s` | %s | %s | %s |' % (
            _cell(row['ruta']), row['bytes'], row['sha256'],
            _cell(row['extension']), row['familia'], _cell(row['firma'])))
    metadata_rows = [row for row in report['archivos'] if row.get('metadatos')]
    if metadata_rows:
        lines.extend(['', '## Metadatos (exiftool, subconjunto)', '',
                      '| Ruta | Campos |', '|---|---|'])
        for row in metadata_rows:
            fields = ', '.join('%s=%s' % (key, value)
                               for key, value in sorted(row['metadatos'].items()))
            lines.append('| %s | %s |' % (_cell(row['ruta']), _cell(fields, 400)))
    if report['archivos'] and any('duplicado_de' in row for row in report['archivos']):
        lines.extend(['', '## Duplicados exactos (mismo SHA-256)', ''])
        for row in report['archivos']:
            if 'duplicado_de' in row:
                lines.append('- %s = %s' % (row['ruta'], row['duplicado_de']))
    lines.append('')
    with _open_new(path) as stream:
        stream.write('\n'.join(lines))
        stream.flush()
        os.fsync(stream.fileno())


def _cell(value, limit=160):
    text = _clean_text(value, limit).replace('|', '\\|')
    return text


def check_api(api_base, delay):
    """Destino admisible: solo HTTPS a VirusTotal o loopback explícito."""
    parsed = urllib.parse.urlparse(api_base)
    if parsed.scheme not in ('https', 'http') or not parsed.hostname:
        raise Unsafe('base de API inválida')
    if parsed.hostname not in LOOPBACK:
        if parsed.scheme != 'https' or not parsed.hostname.endswith('virustotal.com'):
            raise Unsafe('la clave solo se envía a VirusTotal por HTTPS o a loopback')
        if delay < 15:
            raise Unsafe('la API pública limita a 4 consultas/minuto; usa --delay >= 15')
    return parsed


def vt_lookup(report_path, json_path, md_path, api_base, delay, limit):
    key = os.environ.get(VT_KEY, '')
    if not key or any(ord(c) < 33 or ord(c) == 127 for c in key) or not 20 <= len(key) <= 200:
        raise Unsafe('%s ausente o con formato inesperado; no se consulta nada' % VT_KEY)
    check_api(api_base, delay)
    source = _path(report_path)
    with open(source, encoding='utf-8') as stream:
        data = json.load(stream)
    files = data.get('archivos')
    if not isinstance(files, list):
        raise Unsafe('el informe de triaje no tiene lista de archivos')
    # Se enlaza el informe consultado por hash: el run no copia el fichero ajeno.
    source_sha, source_size = _digest(source)
    hashes = []
    for row in files:
        digest = row.get('sha256') if isinstance(row, dict) else None
        if (isinstance(digest, str) and len(digest) == 64 and
                all(c in '0123456789abcdef' for c in digest) and digest not in hashes):
            hashes.append(digest)
    if limit > 0:
        hashes = hashes[:limit]
    results = []
    stopped = ''
    for index, digest in enumerate(hashes):
        if index and delay:
            # La espera también es la pausa entre consultas ya contabilizadas.
            time.sleep(delay)
        state, detail = _vt_one(api_base, key, digest)
        results.append(dict(sha256=digest, estado=state, **detail))
        if state in ('CLAVE_RECHAZADA', 'LIMITADO', 'SIN_RESPUESTA', 'ERROR'):
            stopped = state
            break
    summary = {}
    for row in results:
        summary[row['estado']] = summary.get(row['estado'], 0) + 1
    report = {'version': VERSION, 'generado_utc': _now(),
              'herramienta': 'forensics_iot.vt',
              'api_base': api_base, 'consultados': len(results),
              'pendientes': max(0, len(hashes) - len(results)),
              'detenido_por': stopped or None,
              'origen': {'run': source.parent.parent.name,
                         'report_sha256': source_sha, 'report_bytes': source_size},
              'resumen': summary, 'resultados': results,
              'advertencias': [
                  'Solo se envían hashes; el proveedor externo puede registrar la consulta.',
                  'Un veredicto ausente no significa que el archivo sea limpio.',
                  'La clave no se escribe en el informe ni en los logs.']}
    _write_json(json_path, report)
    _write_vt_markdown(md_path, report)
    return 0 if not stopped else 1


def _vt_one(api_base, key, digest):
    url = '%s/files/%s' % (api_base.rstrip('/'), digest)
    request = urllib.request.Request(url, headers={
        'x-apikey': key, 'accept': 'application/json',
        'user-agent': 'forensics08-iot/1'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read(2 * 1024 * 1024).decode('utf-8', 'replace'))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return 'NO_CONOCIDO', dict(motivo='el proveedor no tiene ese hash')
        if error.code in (401, 403):
            return 'CLAVE_RECHAZADA', dict(motivo='la clave fue rechazada; revisa VT_API_KEY')
        if error.code == 429:
            return 'LIMITADO', dict(motivo='cuota agotada; reintenta más tarde')
        return 'ERROR', dict(motivo='respuesta HTTP %d' % error.code)
    except (urllib.error.URLError, OSError, ValueError):
        return 'SIN_RESPUESTA', dict(motivo='sin respuesta válida del proveedor')
    attributes = payload.get('data', {}).get('attributes', {})
    stats = attributes.get('last_analysis_stats', {})
    if not isinstance(stats, dict):
        stats = {}
    counts = {}
    for name in ('malicious', 'suspicious', 'harmless', 'undetected', 'timeout'):
        value = stats.get(name, 0)
        counts[name] = value if type(value) is int and value >= 0 else 0
    total = sum(counts.values())
    if counts['malicious'] > 0:
        state = 'MALICIOSO'
    elif counts['suspicious'] > 0:
        state = 'SOSPECHOSO'
    elif total == 0:
        state = 'SIN_ANALISIS'
    elif counts['undetected'] + counts['harmless'] > 0:
        state = 'SIN_DETECCIONES'
    else:
        state = 'SIN_ANALISIS'
    last = attributes.get('last_analysis_date')
    return state, dict(maliciosos=counts['malicious'], sospechosos=counts['suspicious'],
                       indetectados=counts['undetected'], total_motores=total,
                       ultimo_analisis_utc=(datetime.fromtimestamp(last, timezone.utc)
                                            .replace(microsecond=0).isoformat().replace('+00:00', 'Z')
                                            if type(last) is int and last > 0 else None))


def _write_vt_markdown(path, report):
    lines = ['# Consulta VirusTotal (solo hashes)', '',
             '- Generado (UTC): %s' % report['generado_utc'],
             '- API: %s' % report['api_base'],
             '- Run de triaje: %s' % report['origen']['run'],
             '- SHA-256 del informe consultado: `%s`' % report['origen']['report_sha256'],
             '- Consultados: %d; pendientes: %d' % (report['consultados'], report['pendientes']),
             '']
    if report['detenido_por']:
        lines.extend(['La tanda se detuvo por: **%s**.' % report['detenido_por'], ''])
    lines.extend(report['advertencias'])
    lines.extend(['', '## Resultados', '',
                  '| SHA-256 | Estado | Maliciosos | Sospechosos | Motores |',
                  '|---|---|---|---|---|'])
    for row in report['resultados']:
        lines.append('| `%s` | %s | %s | %s | %s |' % (
            row['sha256'], row['estado'], row.get('maliciosos', '—'),
            row.get('sospechosos', '—'), row.get('total_motores', '—')))
    lines.append('')
    with _open_new(path) as stream:
        stream.write('\n'.join(lines))
        stream.flush()
        os.fsync(stream.fileno())


def _mounts(mounts_path):
    sources = []
    try:
        text = Path(mounts_path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        raise Unsafe('no se pudieron leer los montajes del sistema')
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        sources.append((fields[0], fields[1]))
    return sources


def _mounted_numbers(mounts_path):
    """(maj,min) de cada origen que sea un dispositivo de bloque + rutas críticas."""
    numbers = set()
    for source, _mountpoint in _mounts(mounts_path):
        if not source.startswith('/'):
            continue
        try:
            info = os.stat(source)
        except OSError:
            continue
        if stat.S_ISBLK(info.st_mode):
            numbers.add((os.major(info.st_rdev), os.minor(info.st_rdev)))
        elif stat.S_ISREG(info.st_mode):
            # Los montajes por fichero (por ejemplo loop) no son soportes físicos.
            continue
    for critical in ('/', '/boot', '/usr', '/home', '/var', '/etc', '/tmp', '/root'):
        try:
            info = os.stat(critical)
        except OSError:
            continue
        # st_dev de un punto montado es el dev_t del sistema de archivos; para
        # un FS sobre bloque coincide con el rdev del dispositivo que lo respalda.
        numbers.add((os.major(info.st_dev), os.minor(info.st_dev)))
    return numbers


def _partition_numbers(sys_block, name):
    numbers = set()
    base = Path(sys_block) / name
    if not base.is_dir():
        return numbers
    for child in base.iterdir():
        devfile = child / 'dev'
        try:
            text = devfile.read_text()
        except OSError:
            continue
        parts = text.strip().split(':')
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            numbers.add((int(parts[0]), int(parts[1])))
    return numbers


def device_guard(source, mode, size_mib, mounts_path, sys_block):
    target = _path(source)
    info = target.lstat()
    if not stat.S_ISBLK(info.st_mode):
        raise Unsafe('la fuente no es un dispositivo de bloque')
    name = target.name
    if any(name.startswith(prefix) for prefix in
           ('loop', 'ram', 'dm-', 'md', 'sr', 'zram', 'nbd')):
        raise Unsafe('se rechazan dispositivos virtuales o de solo lectura (%s)' % name)
    numbers = _mounted_numbers(mounts_path)
    own = {(os.major(info.st_rdev), os.minor(info.st_rdev))}
    partitions = _partition_numbers(sys_block, name)
    busy = (own | partitions) & numbers
    if busy:
        raise Unsafe('el dispositivo o una de sus particiones está montado; '
                     'desmóntalo antes de continuar')
    size_bytes = None
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        fd = None
    if fd is not None:
        try:
            size_bytes = os.lseek(fd, 0, os.SEEK_END)
        except OSError:
            size_bytes = None
        finally:
            os.close(fd)
    if not size_bytes or size_bytes <= 0:
        raise Unsafe('no se pudo determinar el tamaño del dispositivo')
    size_mib_real = size_bytes // MIB
    if mode == 'sterilize':
        if size_mib is None:
            raise Unsafe('indica --size-mib %d (tamaño observado) para confirmar '
                         'que es el soporte correcto' % size_mib_real)
        if size_mib != size_mib_real:
            raise Unsafe('el tamaño indicado no coincide: usa --size-mib %d' % size_mib_real)
    else:
        if size_mib is not None and size_mib != size_mib_real:
            raise Unsafe('el tamaño indicado no coincide: usa --size-mib %d' % size_mib_real)
    return {'source': str(target), 'name': name, 'size_bytes': size_bytes,
            'size_mib': size_mib_real,
            'rdev': '%d:%d' % (os.major(info.st_rdev), os.minor(info.st_rdev)),
            'particiones': ['%d:%d' % pair for pair in sorted(partitions)]}


def zero_check(source, window=CHUNK):
    target = _path(source)
    with open(target, 'rb') as stream:
        head = stream.read(window)
        if not head:
            raise Unsafe('dispositivo vacío')
        if any(head):
            raise Unsafe('el inicio del soporte no está a cero')
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        if size > window:
            stream.seek(max(window, size - window))
            tail = stream.read(window)
            if any(tail):
                raise Unsafe('el final del soporte no está a cero')
    return {'inicio_cero': True, 'bytes_ventana': window}


def fs_check(source, expected):
    target = _path(source)
    with open(target, 'rb') as stream:
        boot = stream.read(512)
    if len(boot) < 512:
        raise Unsafe('no se pudo leer el sector de arranque')
    label16 = boot[54:62].decode('latin-1')
    label32 = boot[82:90].decode('latin-1')
    observed = None
    if label32.startswith('FAT32'):
        observed = 'vfat32'
    elif label16.startswith('FAT16'):
        observed = 'vfat16'
    elif label16.startswith('FAT12') or boot[54:57].startswith(b'FAT'):
        observed = 'vfat12'
    if expected == 'vfat':
        if observed is None:
            raise Unsafe('la firma del sistema de archivos no es FAT')
    elif observed != expected:
        raise Unsafe('la firma observada (%s) no es la esperada' % (observed or 'desconocida'))
    return {'observado': observed}


def receipt(out, device, size_mib, state, phases, details):
    parsed = {}
    for token in phases:
        name, _, rc = token.partition('=')
        if not name or not rc.isdigit():
            raise Unsafe('fase de recibo inválida')
        parsed[name] = int(rc)
    payload = {'version': VERSION, 'generado_utc': _now(),
               'herramienta': 'forensics_iot.sterilize',
               'dispositivo': _clean_text(device, 120), 'size_mib': size_mib,
               'estado': state, 'fases': parsed,
               'detalles': [_clean_text(item, 300) for item in details],
               'advertencias': [
                   'No es evidencia ni certifica un borrado seguro normativo.',
                   'Un fallo a mitad deja el soporte en estado intermedio.',
                   'El recibo se guarda fuera del almacén de runs.']}
    _write_json(out, payload)
    return 0


def report_path(run_dir, name='report.json'):
    data_path = _path(run_dir)
    if data_path.name == 'run.json':
        data_path = data_path.parent
    manifest = data_path / 'run.json'
    try:
        with open(_path(manifest), encoding='utf-8') as stream:
            data = json.load(stream)
    except (OSError, ValueError):
        raise Unsafe('el run indicado no es legible') from None
    if not isinstance(data, dict):
        raise Unsafe('el run indicado no es legible')
    if data.get('operation') != 'triage' or data.get('finished') is None:
        raise Unsafe('el run indicado no es un triaje finalizado')
    references = [ref for step in data.get('steps', []) for ref in step.get('artifacts', [])
                  if ref.get('root') == 'analysis' and ref.get('path') == name]
    if len(references) != 1:
        raise Unsafe('el run no publicó %s' % name)
    return str(data_path / 'analysis' / name)


def mkdir_private(path):
    target = _path(path)
    if not target.parent.exists():
        mkdir_private(str(target.parent))
    if target.exists():
        if not target.is_dir():
            raise Unsafe('existe y no es un directorio')
    else:
        target.mkdir(mode=0o700)
    if stat.S_IMODE(target.lstat().st_mode) != 0o700:
        raise Unsafe('el directorio existente no tiene permisos 700')
    return str(target)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Soporte IoT/portátil del módulo 08')
    subs = parser.add_subparsers(dest='command', required=True)

    item = subs.add_parser('mkdir')
    item.add_argument('--path', required=True)

    item = subs.add_parser('reserve')
    item.add_argument('--path', required=True)

    item = subs.add_parser('triage')
    item.add_argument('--root', required=True)
    item.add_argument('--json', required=True)
    item.add_argument('--md', required=True)
    item.add_argument('--investigator', default='')
    item.add_argument('--exiftool', action='store_true')
    item.add_argument('--exiftool-limit', type=int, default=200)

    item = subs.add_parser('vt')
    item.add_argument('--report', required=True)
    item.add_argument('--json', required=True)
    item.add_argument('--md', required=True)
    item.add_argument('--api-base', default=VT_BASE)
    item.add_argument('--delay', type=float, default=16)
    item.add_argument('--limit', type=int, default=4)

    item = subs.add_parser('vt-check')
    item.add_argument('--api-base', default=VT_BASE)
    item.add_argument('--delay', type=float, default=16)

    item = subs.add_parser('device-guard')
    item.add_argument('--source', required=True)
    item.add_argument('--mode', choices=('acquire', 'sterilize'), required=True)
    item.add_argument('--size-mib', type=int)
    item.add_argument('--mounts', default='/proc/mounts')
    item.add_argument('--sys-block', default='/sys/class/block')

    item = subs.add_parser('zero-check')
    item.add_argument('--source', required=True)

    item = subs.add_parser('fs-check')
    item.add_argument('--source', required=True)
    item.add_argument('--expected', default='vfat')

    item = subs.add_parser('receipt')
    item.add_argument('--out', required=True)
    item.add_argument('--device', required=True)
    item.add_argument('--size-mib', type=int, required=True)
    item.add_argument('--state', required=True)
    item.add_argument('--phase', action='append', default=[])
    item.add_argument('--detail', action='append', default=[])

    item = subs.add_parser('report-path')
    item.add_argument('--run', required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == 'mkdir':
            print(mkdir_private(args.path))
            return 0
        if args.command == 'reserve':
            with _open_new(args.path):
                pass
            return 0
        if args.command == 'triage':
            if args.exiftool_limit < 0:
                raise Unsafe('límite de metadatos inválido')
            report = triage(args.root, args.json, args.md, args.investigator,
                            args.exiftool, args.exiftool_limit)
            print(json.dumps({'archivos': report['resumen']['total'],
                              'bytes': report['resumen']['bytes']}, sort_keys=True))
            return 0
        if args.command == 'vt':
            return vt_lookup(args.report, args.json, args.md, args.api_base,
                             args.delay, max(0, args.limit))
        if args.command == 'vt-check':
            check_api(args.api_base, args.delay)
            print(json.dumps({'api_base': args.api_base}, sort_keys=True))
            return 0
        if args.command == 'device-guard':
            print(json.dumps(device_guard(args.source, args.mode, args.size_mib,
                                          args.mounts, args.sys_block), sort_keys=True))
            return 0
        if args.command == 'zero-check':
            print(json.dumps(zero_check(args.source), sort_keys=True))
            return 0
        if args.command == 'fs-check':
            print(json.dumps(fs_check(args.source, args.expected), sort_keys=True))
            return 0
        if args.command == 'receipt':
            return receipt(args.out, args.device, args.size_mib, args.state,
                           args.phase, args.detail)
        if args.command == 'report-path':
            print(report_path(args.run))
            return 0
        raise Unsafe('subcomando desconocido')
    except Unsafe as error:
        print('NO_EVALUABLE: %s' % error, file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError) as error:
        print('Error de soporte IoT: %s' % type(error).__name__, file=sys.stderr)
        return 1
    except SystemExit:
        raise


if __name__ == '__main__':
    sys.exit(main())

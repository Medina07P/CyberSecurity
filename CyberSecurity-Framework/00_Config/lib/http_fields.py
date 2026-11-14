"""Pure captured-request composition; no transport, files, config or consent.

Names are the raw names emitted by hr_params, not decoded aliases. JSON names
are its dotted scalar paths; selected keys containing dots/empty keys cannot be
represented safely. One/two FieldChanges only. The 1MiB UTF-8 input budget counts
target/body/content-type and each change's location/name/value, including their
NUL frame terminators. The separate JSON-pair wire representation can expand;
extraction has a bounded 8x budget, not an increased composition input allowance.
"""
from dataclasses import dataclass
import json
import re
import sys
from urllib.parse import quote, unquote_plus

MAX_INPUT_BYTES = 1024 * 1024
MAX_PAIR_BYTES = 8 * MAX_INPUT_BYTES + 128


@dataclass(frozen=True)
class FieldChange:
    location: str
    name: str
    value: str


def _text(value):
    if not isinstance(value, str) or '\0' in value:
        raise ValueError('Expected NUL-free text')
    try:
        return len(value.encode('utf-8')) + 1
    except UnicodeError:
        raise ValueError('Expected valid UTF-8 text') from None


def _decoded_name(name):
    if re.search(r'%(?![0-9a-fA-F]{2})', name):
        raise ValueError('Invalid percent-encoded field name')
    try:
        return unquote_plus(name, encoding='utf-8', errors='strict')
    except UnicodeError:
        raise ValueError('Invalid UTF-8 field name') from None


def _pair_index(pairs, name):
    decoded = _decoded_name(name)
    raw_names = [pair.partition('=')[0] for pair in pairs]
    matches = [i for i, raw in enumerate(raw_names) if raw == name]
    aliases = [raw for raw in raw_names if _decoded_name(raw) == decoded]
    if len(matches) != 1 or len(aliases) != 1:
        raise ValueError('Selected field is absent or ambiguous')
    return matches[0]


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError('Non-finite JSON constant')


def _json_load(text):
    try:
        return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (ValueError, RecursionError):
        raise ValueError('Invalid or ambiguous JSON') from None


def _scalar_routes(value, route=(), paths=None):
    if paths is None:
        paths = {}
    if isinstance(value, dict):
        for key, child in value.items():
            _scalar_routes(child, route + (key,), paths)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scalar_routes(child, route + (index,), paths)
    else:
        name = '.'.join(str(part) for part in route)
        paths.setdefault(name, []).append(route)
    return paths


def compose_request(target: str, body: str, content_type: str,
                    changes: tuple[FieldChange, ...]) -> tuple[str, str]:
    """Compose from immutable original strings, or raise ValueError atomically.

    Untouched raw form/query pairs are byte-for-byte unchanged. Replacements are
    literal text encoded once. JSON preserves unrelated values/types, not spacing.
    No caller-owned object or global request state is modified.
    """
    if not isinstance(changes, tuple) or not 1 <= len(changes) <= 2:
        raise ValueError('Expected one or two changes')
    total = sum(_text(value) for value in (target, body, content_type))
    for change in changes:
        if not isinstance(change, FieldChange):
            raise ValueError('Expected FieldChange')
        total += sum(_text(value) for value in (change.location, change.name, change.value))
        if change.location not in ('query', 'form', 'json') or not change.name:
            raise ValueError('Invalid field location/name')
    if total > MAX_INPUT_BYTES:
        raise ValueError('Composition input exceeds 1MiB')
    identities = [(c.location, c.name if c.location == 'json' else _decoded_name(c.name)) for c in changes]
    if len(identities) != len(set(identities)):
        raise ValueError('Changes select the same field')
    media_type = content_type.partition(';')[0].strip().lower()
    base, separator, query = target.partition('?')
    query_pairs = query.split('&') if separator else []
    form_pairs = body.split('&')
    json_value = None
    routes = {}
    if any(c.location == 'json' for c in changes):
        if media_type != 'application/json':
            raise ValueError('JSON field requires JSON content type')
        json_value = _json_load(body)
        try:
            routes = _scalar_routes(json_value)
        except RecursionError:
            raise ValueError('JSON nesting exceeds supported depth') from None
    operations = []
    # Validate ALL identities before applying either change; no partial result.
    for change in changes:
        if change.location == 'query':
            operations.append((change, _pair_index(query_pairs, change.name)))
        elif change.location == 'form':
            if media_type != 'application/x-www-form-urlencoded':
                raise ValueError('Form field requires form content type')
            operations.append((change, _pair_index(form_pairs, change.name)))
        else:
            candidates = routes.get(change.name, [])
            if (len(candidates) != 1 or not candidates[0] or
                    any(isinstance(part, str) and (not part or '.' in part) for part in candidates[0])):
                raise ValueError('Selected JSON scalar path is absent or ambiguous')
            operations.append((change, candidates[0]))
    for change, position in operations:
        if change.location in ('query', 'form'):
            pairs = query_pairs if change.location == 'query' else form_pairs
            pairs[position] = change.name + '=' + quote(change.value, safe='', encoding='utf-8', errors='strict')
        else:
            parent = json_value
            for part in position[:-1]:
                parent = parent[part]
            parent[position[-1]] = change.value
    result_target = base + '?' + '&'.join(query_pairs) if any(c.location == 'query' for c in changes) else target
    result_body = body
    if any(c.location == 'form' for c in changes):
        result_body = '&'.join(form_pairs)
    if any(c.location == 'json' for c in changes):
        try:
            result_body = json.dumps(json_value, ensure_ascii=False, allow_nan=False)
        except (ValueError, RecursionError):
            raise ValueError('JSON serialization failed') from None
    return result_target, result_body


def _read_bounded(stream, limit):
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Input exceeds protocol limit')
    try:
        return data.decode('utf-8')
    except UnicodeError:
        raise ValueError('Expected UTF-8 protocol input') from None


def main(argv=None):
    """Fixed commands only; request values always arrive on stdin, never argv."""
    argv = sys.argv[1:] if argv is None else argv
    try:
        if argv == ['compose']:
            frame = _read_bounded(sys.stdin.buffer, MAX_INPUT_BYTES)
            if not frame.endswith('\0'):
                raise ValueError('Missing terminal NUL')
            parts = frame[:-1].split('\0')
            if len(parts) not in (6, 9):
                raise ValueError('Expected one or two NUL-framed changes')
            changes = tuple(FieldChange(*parts[i:i + 3]) for i in range(3, len(parts), 3))
            target, body = compose_request(parts[0], parts[1], parts[2], changes)
            output = json.dumps({'target': target, 'body': body}, ensure_ascii=False)
        elif argv in (['part-target'], ['part-body']):
            pair = _json_load(_read_bounded(sys.stdin.buffer, MAX_PAIR_BYTES))
            if not isinstance(pair, dict) or set(pair) != {'target', 'body'}:
                raise ValueError('Expected exact target/body pair')
            if any(not isinstance(value, str) or '\0' in value for value in pair.values()):
                raise ValueError('Expected text pair members')
            for value in pair.values():
                _text(value)
            output = pair[argv[0][5:]]
            # Validate encodability before writing anything, including surrogates
            # accepted as JSON escapes by Python's generic decoder.
            output.encode('utf-8')
        else:
            raise ValueError('Unknown fixed composition command')
    except (ValueError, UnicodeError, OSError, RecursionError):
        print('No se pudo componer/extraer la petición: entrada inválida o ambigua.', file=sys.stderr)
        return 2  # diagnostics never echo request values or partial JSON
    sys.stdout.buffer.write(output.encode('utf-8'))
    return 0


if __name__ == '__main__':
    sys.exit(main())

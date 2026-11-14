"""Structural source/row inventory only; not semantic validation or Bash execution.

Supported source shapes are explicit contracts. Unknown shapes fail closed for
manual review rather than silently treating a new option as covered. Source
strings are supplied by tests; this module never opens data or launches tools.
"""
import ast
import re


def function_body(source, name):
    match = re.search(r'^' + re.escape(name) + r'\(\) \{\n(.*?)^\}', source, re.M | re.S)
    if not match:
        raise AssertionError('Missing source function: ' + name)
    return match[1]


def case_body(source, variable, occurrence=0):
    header = r'\bcase\s+["\']?\$' + re.escape(variable) + r'["\']?\s+in\b'
    matches = list(re.finditer(header, source))
    if len(matches) <= occurrence:
        raise AssertionError('Missing case contract: ' + variable)
    start = matches[occurrence].end()
    depth, cursor, parts = 1, start, []
    tokens = r'\bcase\s+["\']?\$[\w]+["\']?\s+in\b|\besac\b'
    for token in re.finditer(tokens, source[start:]):
        begin, end = start + token.start(), start + token.end()
        if token[0] == 'esac':
            depth -= 1
            if depth == 0:
                return '\n'.join(parts + [source[cursor:begin]])
            if depth == 1:
                cursor = end
        else:
            if depth == 1:
                parts.append(source[cursor:begin])
            depth += 1
    raise AssertionError('Unterminated case contract: ' + variable)


def literal_options(source, variable, occurrence=0):
    body = case_body(source, variable, occurrence)
    arms = re.findall(r'(?:^|;;)\s*([^\n;()]+)\)', body, re.M)
    choices = set()
    for arm in arms:
        for item in arm.strip().split('|'):
            item = item.strip().strip('"\'').replace('\\?', '?')
            if item in ('*', ''):
                continue
            if not re.fullmatch(r'[\w!?-]+', item):
                raise AssertionError('Unsupported case arm needs source review: ' + arm)
            choices.add(item)
    if not choices:
        raise AssertionError('No literal options: ' + variable)
    return choices


def printed_options(body):
    # Fixed option labels, not dynamic ${num}/${numero} entries.
    return set(re.findall(r'\$\{[A-Z_]+\}([0-9A-Z?]+)\s*(?:\$\{NC\}|\.)', body))


def require_fragments(body, fragments, namespace):
    for fragment in fragments:
        if fragment not in body:
            raise AssertionError(namespace + ': source shape needs review: ' + fragment)


def selector_equalities(body, variable):
    return set(re.findall(r'["\']?\$' + re.escape(variable) + r'["\']?\s*==\s*["\']?([\w?]+)', body))


def evidence_manage_flags(source):
    """Literal registrations on the manage parser only, AST as data, no imports.

    Reject dynamic flags/aliases rather than losing them. Root and capture/run
    registrations belong to different interfaces, not the manage namespace.
    """
    tree = ast.parse(source)
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_main')
    registrations = [n for n in main.body if isinstance(n, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == 'manage' for t in n.targets)]
    if len(registrations) != 1:
        raise AssertionError('Expected one explicit manage parser')
    call = registrations[0].value
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name) and call.func.value.id == 'commands'
            and call.func.attr == 'add_parser' and len(call.args) == 1
            and isinstance(call.args[0], ast.Constant) and call.args[0].value == 'manage'):
        raise AssertionError('Manage parser ownership changed; review source')
    flags = set()
    for node in ast.walk(main):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == 'manage'
                and node.func.attr == 'add_argument'):
            continue
        if not node.args:
            raise AssertionError('Missing manage flags')
        for arg in node.args:
            if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                    and re.fullmatch(r'--[a-z][a-z-]*|-h', arg.value)):
                raise AssertionError('Dynamic/unknown manage flag alias needs source review')
            if arg.value in flags:
                raise AssertionError('Duplicate manage flag: ' + arg.value)
            flags.add(arg.value)
    if not flags:
        raise AssertionError('Missing manage registrations')
    return frozenset(flags)


def evidence_menu_options(source):
    choices = literal_options(function_body(source, 'evidence_menu'), 'choice')
    return frozenset('0' if value == '!' else value for value in choices)


def special_options(sources):
    """All non-module namespaces from source dispatch or pinned dynamic contract.

    sources keys: manager, wizard, keys, evidence_cli, evidence_menu.
    No configuration/HOME reads; the Bash wrapper is not a flag dispatcher.
    Dynamic list indices are one documented action, not one row per target.
    """
    manager = sources['manager']
    rows = set()
    rows.update(printed_options(function_body(manager, 'main_menu')))
    main = function_body(manager, 'main')
    require_fragments(main, ('[0-9]) choice="0$choice" ;;', '"") : ;;'), 'principal')
    aliases = {'r': 'R', 't': 'T', 'k': 'K', 'q': 'Q', 'salir': 'Q', 'exit': 'Q',
               '??': '?', 'help': '?', 'HELP': '?', 'H': '?', 'h': '?'}
    rows.update(aliases.get(value, value) for value in literal_options(main, 'choice', 1))
    rows.add('principal.vacio')
    report = function_body(manager, 'quick_report')
    rows.update('R.' + value for value in literal_options(report, 'eleccion'))
    rows.update('R.' + value for value in printed_options(report))
    report_cases = set(re.findall(r'\bcase\s+["\']?\$(\w+)["\']?\s+in', report))
    if 'abrir' not in report_cases:
        raise AssertionError('R HTML opening contract changed; review source')
    rows.update('R.' + name for name in report_cases - {'eleccion'})

    keys_menu = function_body(manager, 'keys_menu')
    rows.update('K.' + value for value in literal_options(keys_menu, 'eleccion'))
    rows.update('K.' + value for value in printed_options(keys_menu))
    selector = function_body(manager, 'keys_elegir_herramienta')
    require_fragments(selector, ('numero >= 1', 'numero <= ${#herramientas[@]}',
                                 'KEYS_ELECCION="${herramientas[$((numero - 1))]}"'), 'K selector')
    rows.add('K.herramienta.numero')
    rows.update('K.herramienta.' + value for value in literal_options(selector, 'numero'))

    target = function_body(manager, 'change_target')
    require_fragments(target, ('sel >= 1', 'sel <= ${#lista[@]}',
                               'entry="${lista[$((sel - 1))]}"',
                               'session_set_target "${entry%%|*}"',
                               "IFS= read -r nuevo", 'session_set_target "$nuevo"'), 'T')
    rows.add('T.numero')
    rows.update('T.' + value for value in printed_options(target))
    rows.update('T.' + value for value in selector_equalities(target, 'sel'))
    if re.search(r'\bcase\s+["\']?\$sel["\']?\s+in', target):
        rows.update('T.' + value for value in literal_options(target, 'sel'))
    if 'T.0' not in rows:
        raise AssertionError('T manual-option contract changed')

    listing = function_body(manager, 'run_module_scripts')
    require_fragments(listing, ('choice >= 1', 'choice <= ${#scripts[@]}',
                                'local idx=$((choice - 1))', '"${scripts[$idx]}"'), 'lista')
    rows.add('lista.numero')
    choices = printed_options(listing) | selector_equalities(listing, 'choice')
    rows.update('lista.' + value.upper() for value in choices)
    # If a future refactor adds case dispatch, its literal options must be covered.
    if re.search(r'\bcase\s+"?\$choice"?\s+in', listing):
        rows.update('lista.' + value.upper() for value in literal_options(listing, 'choice'))

    wizard = function_body(sources['wizard'], 'main')
    rows.update('00.wizard.' + value for value in literal_options(wizard, 'resp'))
    prompts = set(re.findall(r'resp=\$\(wz_ask "([^"\n]+)"', wizard))
    prompt_contract = {
        '¿Añadir a la lista actual (1) o empezar una nueva (2)? (0 = salir)',
        '⚠️  Ya existe ${host}:${puerto}. ¿Añadir igualmente? (s/n)',
        '¿Otro objetivo? (s/n)', '¿Correcto? (s/n)',
        '¿Escribir ${#WZ_LINES[@]} objetivo(s)? (s/n)',
    }
    if prompts != prompt_contract:
        raise AssertionError('00.wizard confirmation prompts changed; review contract/rows')
    rows.add('00.wizard.confirmar')

    tree = ast.parse(sources['keys'])
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    for call in ast.walk(main):
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == 'add_parser':
            if not call.args or not isinstance(call.args[0], ast.Constant) or not isinstance(call.args[0].value, str):
                raise AssertionError('Dynamic keys subcommand needs explicit source review')
            rows.add('00.keys.' + call.args[0].value)

    aliases = {'-h': 'help'}
    for flag in evidence_manage_flags(sources['evidence_cli']):
        if flag.startswith('--'):
            rows.add('10.' + flag[2:])
        elif flag in aliases:
            rows.add('10.' + aliases[flag])
        else:
            raise AssertionError('Unknown evidence alias needs explicit contract: ' + flag)
    rows.update('10.' + value for value in evidence_menu_options(sources['evidence_menu']))
    return frozenset(rows)

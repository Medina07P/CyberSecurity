"""Pure plan construction; previews inspect tool/path metadata, never data content."""
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

from .catalog import availability, get_action
from .model import Plan, PlanError, RuntimeContext, Step
from .validation import validate


def _step(id, action, inputs, depends_on=()):
    spec = get_action(action)
    if not isinstance(inputs, Mapping) or set(inputs) - set(spec.input_types):
        raise PlanError(f'{id}: claves de inputs no admitidas')
    values = {key: validate(spec.input_types[key], value) for key, value in inputs.items()}
    if action in ('ssh_enum', 'ssh_attempts'):
        values.setdefault('port', 22)
    missing = set(spec.required) - set(values)
    if missing:
        raise PlanError(f'{id}: faltan inputs: {", ".join(sorted(missing))}')
    if 'url' in values and urlsplit(values['url']).hostname != values['target']:
        raise PlanError(f'{id}: URL y target no concordantes')
    if action == 'sqlmap_request' and 'table' in values:
        table = values['table']
        if '.' not in table and 'database' not in values:
            raise PlanError(f'{id}: table requiere database o base.tabla')
        if '.' in table and 'database' in values and table.split('.')[0] != values['database']:
            raise PlanError(f'{id}: database y table no concordantes')
    if not isinstance(depends_on, (list, tuple)):
        raise PlanError(f'{id}: depends_on debe ser lista')
    dependencies = tuple(validate('id', dep) for dep in depends_on)
    if len(set(dependencies)) != len(dependencies):
        raise PlanError(f'{id}: dependencia duplicada')
    return Step(validate('id', id), action, values, dependencies)


def validate_plan(plan: Plan) -> Plan:
    """Canonicalize and stably topologically sort an immutable plan."""
    if not isinstance(plan, Plan) or not isinstance(plan.name, str) or not plan.name.strip():
        raise PlanError('Nombre de plan inválido')
    if any(ord(c) < 32 or ord(c) == 127 for c in plan.name):
        raise PlanError('Nombre de plan con controles')
    if type(plan.timeout) is not int:
        raise PlanError('Timeout debe ser entero')
    timeout = validate('timeout', plan.timeout)
    if len(plan.steps) > 64:
        raise PlanError('Máximo 64 pasos')
    steps = []
    for step in plan.steps:
        if not isinstance(step, Step):
            raise PlanError('Paso inválido')
        steps.append(_step(step.id, step.action, step.inputs, step.depends_on))
    ids = {step.id for step in steps}
    if len(ids) != len(steps):
        raise PlanError('Id duplicado')
    for step in steps:
        if set(step.depends_on) - ids:
            raise PlanError(f'{step.id}: dependencia desconocida')
    ordered, done = [], set()
    while steps:
        for index, step in enumerate(steps):
            if set(step.depends_on) <= done:
                ordered.append(steps.pop(index))
                done.add(step.id)
                break
        else:
            raise PlanError('Ciclo de dependencias')
    return Plan(plan.name, tuple(ordered), timeout)


def build_plan(selector: str, inputs: Mapping[str, object]) -> Plan:
    """Build conservative profiles or a single explicitly selected catalog action.

    Shared inputs are defaults, not templates. A profile never adds sensitive
    actions based merely on the presence of their inputs.
    """
    if not isinstance(inputs, Mapping):
        raise PlanError('Inputs debe ser mapping')
    profiles = {'quick': ('ping', 'scan_basic'), 'full': ('ping', 'scan_basic', 'db_versions'),
                'recon': ('ping', 'scan_basic'), 'scan': ('scan_basic',),
                'enum': ('ssh_enum', 'smb_shares', 'db_versions'),
                'web': ('web_tech', 'web_scan'), 'post': ()}
    if selector == 'exploit':
        action = inputs.get('action')
        if action not in ('ssh_attempts', 'sqlmap_request', 'exploit_lookup'):
            raise PlanError('Exploit exige action explícita')
        actions = [action]
    elif selector in profiles:
        actions = list(profiles[selector])
    else:
        get_action(selector)
        actions = [selector]
    configurable = selector in ('quick', 'full')
    if 'include_config' in inputs and type(inputs['include_config']) is not bool:
        raise PlanError('include_config debe ser bool')
    if configurable:
        if 'domain' in inputs:
            actions.insert(0, 'osint_domains')
        if inputs.get('include_config', False):
            actions.insert(0, 'config_check')
        if 'url' in inputs:
            actions.append('web_tech')
        if 'report_input' in inputs:
            actions.append('report')
    elif selector == 'enum' and 'url' in inputs:
        actions.append('web_tech')
    allowed = {key for action in actions for key in get_action(action).input_types}
    # Post is a non-executable guide; a session target may still be displayed by CLI.
    if selector == 'post':
        allowed.add('target')
    controls = {'include_config'} if configurable else set()
    if selector == 'exploit':
        controls.add('action')
    if set(inputs) - allowed - controls:
        raise PlanError('Inputs no admitidos para selector')
    steps = []
    for action in actions:
        values = {key: value for key, value in inputs.items() if key in get_action(action).input_types}
        # Sequential chain preserves stop-on-failure semantics and explicit order.
        dependencies = (steps[-1].id,) if steps else ()
        steps.append(_step(action, action, values, dependencies))
    return validate_plan(Plan(selector, tuple(steps), 3600 if selector == 'full' else 600))


def _path_status(path):
    # No resolve/open: preserve lexical identity for descriptor-based preflight.
    try:
        if any(part.is_symlink() for part in (path, *path.parents)):
            return 'enlace inválido para preflight'
    except OSError:
        pass
    return 'pendiente de preflight (tipo/identidad/contenido no verificados)'


def render_plan(plan: Plan, ctx: RuntimeContext) -> str:
    """Describe intent, gates and limitations; never authorize or run anything."""
    plan = validate_plan(plan)
    found = availability(ctx)
    lines = [f'Plan: {plan.name}; timeout global: {plan.timeout} s',
             'Solo preview; no ejecución ni autorización. Rutas pendientes de preflight.']
    if not plan.steps:
        lines.append('Guía post: consultar 06; plan no ejecutable.')
    for step in plan.steps:
        spec = get_action(step.action)
        gates = spec.gates
        if step.action == 'sqlmap_request':
            gates = ('sqlmap_probe',)
            if 'database' in step.inputs:
                gates += ('sqlmap_enum',)
            if 'table' in step.inputs:
                gates += ('sqlmap_dump',)
        lines.append(f'{step.id}: {step.action}; depende: {", ".join(step.depends_on) or "ninguno"}')
        lines.append(f'  backend: {"disponible en PATH (no probado)" if found[step.action] else "ausente"}; '
                     f'red: {"requiere autorización explícita" if spec.network else "no"}; '
                     f'gates: {", ".join(gates) or "ninguno"}')
        if step.action == 'sqlmap_request':
            lines.append('  sqlmap_replay: condicional al preflight de contexto; no se lee request en preview.')
        for key, value in step.inputs.items():
            if isinstance(value, Path):
                description = f'{value} [{_path_status(value)}]'
            elif key == 'ports':
                description = f'{len(value)} puertos: ' + ','.join(map(str, value))
            else:
                description = str(value)
            lines.append(f'  {key}: {description}')
        lines.extend((f'  efectos: {spec.effects}', f'  límites: {spec.limitations}'))
    return '\n'.join(lines)

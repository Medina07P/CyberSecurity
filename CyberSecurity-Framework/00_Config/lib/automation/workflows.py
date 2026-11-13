"""Bounded strict YAML v1 ingestion; only the selected YAML is opened."""
import os
from pathlib import Path
from collections.abc import Mapping

from .catalog import get_action
from .model import Plan, PlanError
from .planner import _step, validate_plan
from .validation import validate


def _load(text):
    try:
        import yaml
    except ImportError:
        raise PlanError('Workflows requieren PyYAML; perfiles built-in disponibles') from None

    class LimitedLoader(yaml.SafeLoader):
        def compose_node(self, parent, index):
            if self.check_event(yaml.AliasEvent):
                raise PlanError('YAML aliases no admitidos')
            event = self.peek_event()
            if getattr(event, 'tag', None) is not None or getattr(event, 'anchor', None) is not None:
                raise PlanError('YAML tags/anchors no admitidos')
            self.depth += 1
            try:
                if self.depth > 12:
                    raise PlanError('YAML profundidad máxima 12')
                return super().compose_node(parent, index)
            finally:
                self.depth -= 1

        def construct_mapping(self, node, deep=False):
            result = {}
            for key_node, value_node in node.value:
                if not isinstance(key_node, yaml.ScalarNode) or key_node.tag != 'tag:yaml.org,2002:str':
                    raise PlanError('YAML claves deben ser texto')
                key = self.construct_object(key_node, deep=deep)
                if key in result:
                    raise PlanError('YAML clave duplicada')
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    loader = None
    try:
        loader = LimitedLoader(text)
        loader.depth = 0
        return loader.get_single_data()
    except yaml.YAMLError as error:
        raise PlanError('YAML inválido') from error
    finally:
        if loader is not None:
            loader.dispose()


def load_workflow(path: Path, defaults: Mapping[str, object]) -> Plan:
    """Apply only admitted, absent defaults; YAML path inputs are YAML-relative.

    CLI default paths retain CLI identity (they are not relative to the YAML).
    No input path is resolved or opened here. Unsafe path identities remain for
    preflight to reject; preview can show symlink metadata without following it.
    """
    # Diagnose the optional dependency even when the selected path is absent.
    try:
        import yaml  # noqa: F401
    except ImportError:
        raise PlanError('Workflows requieren PyYAML; perfiles built-in disponibles') from None
    if not isinstance(defaults, Mapping):
        raise PlanError('Defaults debe ser mapping')
    path = Path(os.path.abspath(path))  # lexical absolute path, never resolve()
    try:
        with path.open('rb') as stream:
            content = stream.read(65537)
        if len(content) > 65536:
            raise PlanError('YAML máximo 64 KiB')
        text = content.decode('utf-8')
    except (OSError, UnicodeError) as error:
        raise PlanError('No se puede leer workflow UTF-8') from error
    data = _load(text)
    if not isinstance(data, dict) or set(data) != {'name', 'version', 'timeout', 'steps'}:
        raise PlanError('Esquema workflow inválido: name/version/timeout/steps requeridos')
    if type(data['version']) is not int or data['version'] != 1:
        raise PlanError('Versión workflow debe ser 1')
    if not isinstance(data['steps'], list) or not 1 <= len(data['steps']) <= 64:
        raise PlanError('Workflow debe contener 1–64 pasos')
    steps = []
    for item in data['steps']:
        if (not isinstance(item, dict) or not {'id', 'action'} <= set(item)
                or set(item) - {'id', 'action', 'inputs', 'depends_on'}):
            raise PlanError('Esquema step inválido')
        spec = get_action(item['action'])
        explicit = item.get('inputs', {})
        if not isinstance(explicit, dict) or set(explicit) - set(spec.input_types):
            raise PlanError('Inputs workflow no admitidos')
        values = {key: value for key, value in defaults.items() if key in spec.input_types}
        for key, value in explicit.items():
            if spec.input_types[key] == 'path':
                value = validate('path', value)
                if not value.is_absolute():
                    value = path.parent / value
            values[key] = value
        steps.append(_step(item['id'], item['action'], values, item.get('depends_on', ())))
    return validate_plan(Plan(data['name'], tuple(steps), data['timeout']))

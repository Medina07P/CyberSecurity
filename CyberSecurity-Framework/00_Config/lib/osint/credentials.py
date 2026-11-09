"""Solo lectura; misma precedencia que el registro y theHarvester."""
from pathlib import Path
import yaml


def _yaml(path):
    try:
        data = yaml.safe_load(Path(path).read_text(encoding='utf-8'))
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeError, yaml.YAMLError):
        raise ValueError('Configuración de claves ilegible (contenido omitido)') from None
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError('Configuración de claves debe ser un mapa')
    return data


def load_credentials(registry, harvester_dirs):
    registered = _yaml(registry).get('theharvester', {})
    external = {}
    for directory in harvester_dirs:
        path = Path(directory) / 'api-keys.yaml'
        if path.exists():
            data = _yaml(path)
            external = data.get('apikeys', data)
            break
    if not isinstance(registered, dict) or not isinstance(external, dict):
        raise ValueError('Sección de claves debe ser un mapa')
    result = {}
    for provider in ('brave', 'github', 'hunter'):
        for section in (registered, external):
            item = section.get(provider, {})
            value = item.get('key', '') if isinstance(item, dict) else ''
            if isinstance(value, str) and value.strip():
                value = value.strip()
                if any(c.isspace() for c in value):
                    raise ValueError('Clave API con formato inválido')
                result[provider] = value
                break
    return result

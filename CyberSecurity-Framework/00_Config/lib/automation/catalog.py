"""Closed action schemas and non-executing dependency discovery.

Availability maps action ids to required-tool presence, not operational support.
Optional tools remain coverage omissions, never required dependencies.
"""
import importlib.util
import shutil
from types import MappingProxyType
from typing import Mapping

from .model import ActionSpec, PlanError, RuntimeContext


_BASH = ('bash', 'python3', 'dirname')
_SCANNER = _BASH + ('mkdir', 'mktemp', 'date', 'cat', 'rm')
_ENUM = _BASH + ('mkdir', 'mktemp', 'date', 'cat', 'rm', 'rmdir', 'timeout')
_SQLMAP = _BASH + ('sqlmap', 'timeout', 'mktemp', 'mkdir', 'chmod', 'date',
                   'awk', 'tr', 'sed', 'cp', 'basename', 'grep', 'rm',
                   'cat', 'wc', 'tail', 'od')


def _action(id, inputs, required, gates, tools, network, effects, limitations):
    return ActionSpec(id, inputs, required, gates, tools, network, effects, limitations)


_ACTIONS = (
    _action('ping', {'target': 'target'}, ('target',), (), ('ping',), True,
            'Un paquete ICMP al objetivo.', 'ICMP filtrado no prueba host apagado.'),
    _action('scan_basic', {'target': 'target'}, ('target',), ('scanner',),
            _SCANNER + ('nmap',), True,
            'Hoja Nmap básica: 100 puertos TCP y versión ligera; salidas compartidas de 03.',
            'Requiere lock de 09; no NSE ni cobertura TCP completa.'),
    _action('ports_full', {'target': 'target'}, ('target',), ('full_ports',), ('nmap',), True,
            'Nmap TCP completo, XML privado.', '65535 puertos; no descubre servicios implícitamente.'),
    _action('services', {'target': 'target', 'ports': 'ports'}, ('target', 'ports'), (), ('nmap',), True,
            'Nmap -Pn -sV sobre puertos explícitos; XML privado.', 'No reutiliza salidas antiguas.'),
    _action('nse_services', {'target': 'target', 'ports': 'ports'}, ('target', 'ports'), ('nse',), ('nmap',), True,
            'Nmap -Pn -sV -sC sobre puertos explícitos; XML privado.', 'NSE puede tener efectos activos.'),
    _action('os_detect', {'target': 'target'}, ('target',), ('os',), ('nmap',), True,
            'Nmap -Pn -O; XML privado.', 'Sin sudo automático; puede requerir privilegios.'),
    _action('scan_vuln', {'target': 'target', 'ports': 'ports'}, ('target', 'ports'), ('nse_vuln',), ('nmap',), True,
            'Nmap -Pn -sV --script vuln sobre puertos explícitos; XML privado.',
            'Scripts activos; salida no equivale a vulnerabilidad confirmada.'),
    _action('ssh_enum', {'target': 'target', 'port': 'port'}, ('target',), ('users',),
            _ENUM + ('nmap',), True,
            'Hoja SSH: versión, autenticación, usuarios y algoritmos.',
            'Puerto por defecto 22 visible en el plan; incluye enumeración de usuarios.'),
    _action('smb_shares', {'target': 'target'}, ('target',), ('anonymous_access',), ('smbclient',), True,
            'smbclient -L //<target> -N.', 'Solo shares anónimos; no RPC adicional.'),
    _action('db_versions', {'target': 'target'}, ('target',), (), ('nmap',), True,
            'Nmap -Pn -sV -p 3306,5432,6379; XML privado.', 'Sin contraseñas, consultas ni KEYS.'),
    _action('web_tech', {'target': 'target', 'url': 'url'}, ('target', 'url'), (), ('whatweb',), True,
            'WhatWeb -a 3 contra URL explícita.', 'URL y target deben concordar; no adivina esquema.'),
    _action('web_scan', {'target': 'target', 'url': 'url'}, ('target', 'url'), ('web_scan',),
            _SCANNER + ('nikto', 'grep', 'mv', 'rmdir'), True,
            'Hoja Nikto activa contra URL explícita.',
            'URL y target deben concordar; hoja rechaza comas literales y requiere evaluación completa.'),
    _action('smb_audit', {'target': 'target'}, ('target',), ('smb_users',),
            _ENUM + ('nmap', 'rpcclient', 'smbclient'), True,
            'Hoja SMB avanzada: usuarios null/RPC, shares y NSE.',
            'enum4linux opcional, omisión visible; no sustituye smb_shares.'),
    _action('osint_domains', {'domain': 'domain'}, ('domain',), ('osint',), _BASH, True,
            'Hoja OSINT con dominio explícito y salida privada.',
            'Requiere PyYAML (yaml); whois/whatweb/dig opcionales, con cobertura omitida; '
            'no importar backends al comprobar.'),
    _action('config_check', {}, (), ('config_read',), _BASH + ('wc', 'basename'), False,
            'Validador local lee configuración y cuenta wordlists solo en ejecución.',
            'Opt-in; planificación no lee datos ni certifica autorización.'),
    _action('ssh_attempts', {'target': 'target', 'port': 'port', 'account': 'account',
                           'wordlist': 'path', 'max_attempts': 'max_attempts', 'max_seconds': 'max_seconds'},
            ('target', 'account', 'wordlist', 'max_attempts', 'max_seconds'),
            ('credential_attempts',), ('hydra',), True,
            'Hydra SSH una cuenta explícita; -t 1 -f, copia privada acotada de candidatos.',
            '1–200 intentos, 1–300 s; cuenta puede bloquearse; puerto 22 por defecto visible.'),
    _action('sqlmap_request', {'target': 'target', 'request_file': 'path', 'scheme': 'scheme',
                             'database': 'database', 'table': 'table'},
            ('target', 'request_file', 'scheme'),
            ('sqlmap_probe', 'sqlmap_replay', 'sqlmap_enum', 'sqlmap_dump'), _SQLMAP, True,
            'Hoja SQLmap sobre .req regular explícito; replay/enum/dump separados; muestra 50 filas.',
            'Gates adicionales condicionales; table requiere database o base.tabla. '
            'Sin directorio/stdin; preflight comprueba autoridad/contexto, nunca lee petición en preview.'),
    _action('exploit_lookup', {'product': 'product'}, ('product',), (), ('searchsploit',), False,
            'Consulta local SearchSploit con producto/versión como argumento único.',
            'No ejecuta exploits; coincidencias no prueban vulnerabilidad.'),
    _action('report', {'target': 'target', 'report_input': 'path'}, ('target', 'report_input'),
            ('report_read',), ('python3',), False,
            'Motor 11 con target, input y salida explícitos.',
            'Lee datos solo al ejecutar; no convierte falta de cobertura en éxito.'),
)
_BY_ID = MappingProxyType({action.id: action for action in _ACTIONS})


def get_action(id: str) -> ActionSpec:
    try:
        return _BY_ID[id]
    except (KeyError, TypeError):
        raise PlanError('Acción desconocida') from None


def missing_python_dependencies(action: str) -> tuple[str, ...]:
    """Discover top-level packages in the current interpreter, without imports.

    Production uses sys.executable. No package probe for builtin-only actions;
    optional workflow YAML loading remains independent of action availability.
    """
    packages = ('yaml',) if action == 'osint_domains' else ()
    return tuple(name for name in packages if importlib.util.find_spec(name) is None)


def availability(ctx: RuntimeContext) -> Mapping[str, bool]:
    """Resolve required executables in the explicit PATH, without launching any.

    Empty PATH means none available; do not fall back to the inherited PATH or cwd.
    No source imports, --version probes or reads of config/evidence are performed.
    """
    paths = [part for part in ctx.path.split(':') if part.startswith('/')]
    path = ':'.join(paths)
    present = {tool: bool(path) and shutil.which(tool, path=path) is not None
               for action in _ACTIONS for tool in action.tools}
    return MappingProxyType({id: all(present[tool] for tool in action.tools)
                            and not missing_python_dependencies(id)
                             for id, action in _BY_ID.items()})

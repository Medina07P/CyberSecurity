"""Pure safe user summary; never reads durable reasons, logs or run content."""
from pathlib import Path
import unicodedata

REASONS = {
    'completed': 'completado', 'cancelled': 'cancelado por señal',
    'timeout': 'tiempo agotado', 'backend_failed': 'fallo de backend',
    'setup_failed': 'fallo de preparación', 'storage_failed': 'fallo de almacenamiento',
}


def render_result(result):
    reason = REASONS.get(result.reason_code, 'no determinado')
    value = f'Resultado: rc={result.rc}; motivo={reason}.'
    path = result.run_dir
    if isinstance(path, Path):
        text = str(path)
        if (path.is_absolute() and len(text) <= 4096 and
                not any(unicodedata.category(char).startswith('C') for char in text)):
            value += '\nRun: ' + text
    return value

"""Configuración del asistente IA local (YAML, sin dependencias nuevas)."""
import os
from pathlib import Path

import yaml

DEFAULTS = {
    "modelo": "qwen2.5:3b",
    "endpoint": "http://127.0.0.1:11434",
    "permitir_endpoint_remoto": False,
    "contexto_max_tokens": 2048,
    "turnos_literales": 4,
    "top_k": 4,
    "incluir_credenciales": False,
}


def default_path() -> Path:
    """AI_CONFIG si está definida; si no, 09_Automation/ai/ai_config.yaml."""
    env = os.environ.get("AI_CONFIG")
    if env:
        return Path(env)
    fw = Path(__file__).resolve().parents[3]
    return fw / "09_Automation" / "ai" / "ai_config.yaml"


def _read(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return data if isinstance(data, dict) else {}


def load(path: Path | None = None) -> dict:
    """Defaults sobrescritos por el fichero; tolera fichero ausente, inválido o
    con un valor mal tipado (se ignora esa clave, nunca revienta más adelante
    con un TypeError críptico al construir el asistente)."""
    cfg = dict(DEFAULTS)
    for k, v in _read(Path(path) if path else default_path()).items():
        if k not in DEFAULTS:
            continue
        default = DEFAULTS[k]
        # bool es subclase de int: no aceptar 0/1 donde se espera un
        # interruptor, ni un booleano donde se espera un número.
        if isinstance(default, bool):
            if isinstance(v, bool):
                cfg[k] = v
        elif isinstance(v, type(default)) and not isinstance(v, bool):
            cfg[k] = v
    return cfg


def save_model(name: str, path: Path | None = None) -> None:
    """Fija el modelo conservando el resto de claves."""
    p = Path(path) if path else default_path()
    cfg = load(p)
    cfg["modelo"] = name
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")
    os.replace(tmp, p)

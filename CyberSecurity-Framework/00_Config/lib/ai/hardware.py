"""Recomendación de modelo local (Ollama) según memoria y GPU. Solo lectura."""
import shutil
from dataclasses import dataclass

# Nombres de modelos del catálogo de Ollama (verificados contra mi conocimiento,
# no contra la red): se fijan aquí para poder cambiarlos en un solo sitio.
MODEL_1B = "llama3.2:1b"
MODEL_3B = "qwen2.5:3b"
MODEL_7B = "qwen2.5:7b"
MODEL_14B = "qwen2.5:14b"


@dataclass(frozen=True)
class Recommendation:
    model: str
    size_label: str
    reason: str
    pull_command: str


def read_mem_available_gib(meminfo_path: str = "/proc/meminfo") -> float:
    """GiB de MemAvailable; 0.0 si el fichero falta o no se puede interpretar."""
    try:
        with open(meminfo_path, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / (1024 * 1024)
    except (OSError, ValueError, IndexError):
        pass
    return 0.0


def has_nvidia_gpu(which=shutil.which) -> bool:
    """Solo comprueba que nvidia-smi exista en PATH; no lo ejecuta."""
    return which("nvidia-smi") is not None


def _rec(model: str, label: str, reason: str) -> Recommendation:
    return Recommendation(model, label, reason, f"ollama pull {model}")


def recommend_model(mem_gib: float, gpu: bool) -> Recommendation:
    """Tabla aproximada: <3 GiB ~1B; 3-7 ~3B; 7-14 ~7B Q4; >14 14B.

    Con GPU NVIDIA se garantiza al menos el modelo de 3B (la VRAM no se mide).
    """
    mem = f"{mem_gib:.1f} GiB libres"
    if mem_gib > 14:
        return _rec(MODEL_14B, "~14B", f"{mem}: caben modelos grandes.")
    if mem_gib >= 7:
        return _rec(MODEL_7B, "~7B", f"{mem}: un modelo de 7B cuantizado cabe con holgura.")
    if mem_gib >= 3 or gpu:
        why = f"{mem}: modelo de ~3B, equilibrio entre calidad y velocidad."
        if gpu and mem_gib < 3:
            why = f"{mem} y GPU NVIDIA detectada: se propone al menos ~3B."
        return _rec(MODEL_3B, "~3B", why)
    return _rec(MODEL_1B, "~1B", f"{mem}: poca memoria, modelo pequeño (respuestas más simples).")

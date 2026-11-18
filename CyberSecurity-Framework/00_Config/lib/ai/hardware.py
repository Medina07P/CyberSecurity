"""Recomendación de modelo local (Ollama) según memoria y GPU. Solo lectura."""
import os
import shutil
from dataclasses import dataclass

# Nombres de modelos del catálogo de Ollama (verificados contra mi conocimiento,
# no contra la red): se fijan aquí para poder cambiarlos en un solo sitio.
MODEL_1B = "llama3.2:1b"
MODEL_3B = "qwen2.5:3b"
MODEL_7B = "qwen2.5:7b"
MODEL_14B = "qwen2.5:14b"

# Vendor ID PCI de AMD, tal como aparece en /sys/class/drm/<tarjeta>/device/vendor.
_AMD_PCI_VENDOR = "0x1002"

# No toda GPU AMD que Linux detecta está soportada por ROCm (el backend que usa
# Ollama): la lista oficial deja fuera chips de consumo recientes (p. ej. RDNA2
# de gama media/baja, gfx1032 entre ellos). Cuando ROCm no reconoce el chip,
# Ollama sigue respondiendo pero por CPU sin avisarlo con claridad — se nota en
# «ollama ps» mostrando 100% CPU. El arreglo conocido (también en Linux, no solo
# Windows) es forzar HSA_OVERRIDE_GFX_VERSION a la versión de un chip soportado
# cercano antes de arrancar «ollama serve»; a veces además hace falta una build
# de rocBLAS con soporte para el chip exacto (paquetes de la comunidad).
AMD_GFX_NOTE = (
    "GPU AMD detectada; Ollama usa ROCm y no todos los chips están en su lista "
    "oficial (p. ej. varias RDNA2 de gama media/baja). Si «ollama ps» muestra "
    "100% CPU en vez de GPU, revisa el log de Ollama por mensajes sobre el chip "
    "y prueba fijar HSA_OVERRIDE_GFX_VERSION a la versión de un chip soportado "
    "cercano (p. ej. 10.3.0) antes de arrancar «ollama serve»."
)


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


def has_amd_gpu(sys_class_drm: str = "/sys/class/drm") -> bool:
    """Lee el vendor PCI de cada tarjeta en /sys/class/drm (0x1002 = AMD).

    No depende de que rocm-smi/amd-smi estén instalados (son paquetes
    aparte del driver): el kernel expone el vendor de cada GPU aunque no haya
    ninguna herramienta de AMD presente. Solo lectura de sysfs, nada se
    ejecuta ni se asume privilegio.
    """
    try:
        entradas = os.listdir(sys_class_drm)
    except OSError:
        return False
    for entrada in entradas:
        # Las tarjetas son "card0", "card1"...; "card0-HDMI-A-1" y similares
        # son conectores, no dispositivos con su propio "device/vendor".
        if not entrada.startswith("card") or "-" in entrada:
            continue
        vendor_path = os.path.join(sys_class_drm, entrada, "device", "vendor")
        try:
            with open(vendor_path, encoding="utf-8") as fh:
                if fh.read().strip().lower() == _AMD_PCI_VENDOR:
                    return True
        except OSError:
            continue
    return False


def _rec(model: str, label: str, reason: str) -> Recommendation:
    return Recommendation(model, label, reason, f"ollama pull {model}")


def recommend_model(mem_gib: float, gpu: bool, amd_gpu: bool = False) -> Recommendation:
    """Tabla aproximada: <3 GiB ~1B; 3-7 ~3B; 7-14 ~7B Q4; >14 14B.

    Con GPU (NVIDIA o AMD) se garantiza al menos el modelo de 3B (la VRAM no
    se mide). Con GPU AMD se añade el aviso de que ROCm no soporta todos los
    chips (ver AMD_GFX_NOTE) — la recomendación de tamaño no cambia por eso,
    solo se explica por qué podría no notarse en velocidad.
    """
    mem = f"{mem_gib:.1f} GiB libres"
    con_gpu = gpu or amd_gpu
    aviso_amd = (" " + AMD_GFX_NOTE) if amd_gpu else ""
    if mem_gib > 14:
        return _rec(MODEL_14B, "~14B", f"{mem}: caben modelos grandes.{aviso_amd}")
    if mem_gib >= 7:
        return _rec(MODEL_7B, "~7B",
                   f"{mem}: un modelo de 7B cuantizado cabe con holgura.{aviso_amd}")
    if mem_gib >= 3 or con_gpu:
        why = f"{mem}: modelo de ~3B, equilibrio entre calidad y velocidad."
        if con_gpu and mem_gib < 3:
            marca = "GPU AMD" if amd_gpu else "GPU NVIDIA"
            why = f"{mem} y {marca} detectada: se propone al menos ~3B."
        return _rec(MODEL_3B, "~3B", why + aviso_amd)
    return _rec(MODEL_1B, "~1B",
               f"{mem}: poca memoria, modelo pequeño (respuestas más simples).{aviso_amd}")

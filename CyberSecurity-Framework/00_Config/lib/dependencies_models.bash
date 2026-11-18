#!/bin/bash
# Catálogo de modelos de Ollama y guardrail de recursos. Solo lo carga el
# gestor (tecla D), junto a dependencies.bash. Las cifras de GB/RAM son
# aproximadas (orden de magnitud de cuantización GGUF Q4_K_M conocida, no
# medidas contra la red): viven aquí, separadas de 00_Config/lib/ai/hardware.py
# (que decide qué modelo general recomendar, no cuánto pesa cada artefacto).

_dependencies_models_self="${BASH_SOURCE[0]:-$0}"
_dependencies_models_self_dir="${_dependencies_models_self%/*}"
[[ "$_dependencies_models_self_dir" != "$_dependencies_models_self" ]] || _dependencies_models_self_dir='.'
DEPENDENCIES_MODELS_LIB_DIR="$(cd "$_dependencies_models_self_dir" && pwd)"
unset _dependencies_models_self _dependencies_models_self_dir

declare -gA DEPENDENCIES_MODEL_CATALOG=(
    [general:1b]='0.7|2|llama3.2:1b'
    [general:3b]='1.9|3|qwen2.5:3b'
    [general:7b]='4.7|8|qwen2.5:7b'
    [general:14b]='9.0|14|qwen2.5:14b'
    [qwen:0.5b]='0.4|1|qwen2.5-coder:0.5b'
    [qwen:1.5b]='1.0|2|qwen2.5-coder:1.5b'
    [qwen:3b]='1.9|3|qwen2.5-coder:3b'
    [qwen:7b]='4.7|8|qwen2.5-coder:7b'
    [qwen:14b]='9.0|14|qwen2.5-coder:14b'
    [qwen:32b]='20|24|qwen2.5-coder:32b'
    [foundation:8b]='5|8|hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M'
    [deephat:7b]='4.7|8|hf.co/liodon-ai/DeepHat-V1-7B-imatrix-GGUF:Q4_K_M'
)
declare -ga DEPENDENCIES_MODEL_ROW_ORDER=(general qwen foundation deephat)

dependencies_model_rows() {
    printf 'general|General (según esta máquina)|Modelo generalista recomendado por el asistente de IA según RAM/GPU; sin entrenamiento específico de seguridad.\n'
    printf 'qwen|Qwen2.5-Coder (oficial, recomendado)|Modelo de código de Alibaba, librería oficial de Ollama; benchmarks de seguridad ofensiva lo señalan por encima de los modelos etiquetados de seguridad. Apache-2.0 salvo el tamaño 3B.\n'
    printf 'foundation|Foundation-Sec-8B-Instruct (Cisco)|Especialista real en ciberseguridad: preentrenado con datos de seguridad por Cisco Foundation AI, Apache-2.0. Tamaño fijo ~8B.\n'
    printf 'deephat|DeepHat / WhiteRabbitNeo (comunidad)|Proyecto de investigación en seguridad presentado sin censura a propósito (barreras de seguridad quitadas deliberadamente); no es una subida oficial de una empresa.\n'
}

dependencies_model_sizes() {
    local fila="$1" clave
    for clave in "${!DEPENDENCIES_MODEL_CATALOG[@]}"; do
        [[ "$clave" == "$fila:"* ]] && printf '%s\n' "${clave#*:}"
    done | sort -V
}

dependencies_model_lookup() {
    local clave="$1:$2"
    [[ -v DEPENDENCIES_MODEL_CATALOG[$clave] ]] || return 1
    printf '%s\n' "${DEPENDENCIES_MODEL_CATALOG[$clave]}"
}

dependencies_general_model_size() {
    python3 -c '
import os, sys
sys.path.insert(0, "'"$DEPENDENCIES_LIB_DIR"'")
from ai.hardware import read_mem_available_gib, has_nvidia_gpu, recommend_model, MODEL_1B, MODEL_3B, MODEL_7B, MODEL_14B
mem = read_mem_available_gib(os.environ.get("DEPENDENCIES_MEMINFO_PATH", "/proc/meminfo"))
rec = recommend_model(mem, has_nvidia_gpu())
print({MODEL_1B: "1b", MODEL_3B: "3b", MODEL_7B: "7b", MODEL_14B: "14b"}.get(rec.model, "3b"))
'
}

dependencies_mem_check() {
    python3 -c '
import os, sys
sys.path.insert(0, "'"$DEPENDENCIES_LIB_DIR"'")
from ai.hardware import read_mem_available_gib
necesaria = float(sys.argv[1])
disponible = read_mem_available_gib(os.environ.get("DEPENDENCIES_MEMINFO_PATH", "/proc/meminfo"))
print(f"{disponible:.1f}")
sys.exit(0 if disponible >= necesaria else 1)
' "$1"
}

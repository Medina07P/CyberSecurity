#!/bin/bash
# ============================================================
#  AI_MENU - Tecla I del gestor: abre el asistente de IA local
#  Se carga con source desde cyber_framework.sh (FRAMEWORK_DIR y los
#  colores los define el gestor). Nunca bloquea ni cierra el gestor.
# ============================================================

ai_menu() {
    local rc=0

    clear_screen
    if ! command -v python3 >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠  El asistente de IA necesita python3 y no está en el PATH.${NC}"
        echo -e "${DIM}Instálalo (p. ej. sudo apt install python3) y vuelve a pulsar I.${NC}"
        return 0
    fi

    # SESSION_FILE es una variable normal del gestor: se pasa al hijo para que
    # lea el mismo objetivo de sesión (sin ella usaría el mismo valor por defecto).
    (cd "$FRAMEWORK_DIR" && SESSION_FILE="$SESSION_FILE" python3 09_Automation/ai/ai_assistant.py)
    rc=$?
    if [[ $rc -ne 0 ]]; then
        echo -e "${YELLOW}El asistente terminó con código $rc.${NC}"
    fi
    return 0
}

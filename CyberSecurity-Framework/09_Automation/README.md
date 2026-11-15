# 09_Automation — planes explícitos

**Verificación Task9 BLOQUEADA (round1):** `tests/run_automation.sh` no lanza
pruebas. Falta una barrera SO heredada revisada para filesystem/red; audithook
no la sustituye. Las pruebas nuevas solo están escritas, sin ejecución. No
reanudar tests/probes por los conteos históricos: decisión del controlador.

Entrada preview-first para acciones de catálogo cerrado, no automatización de
todas las fases ni sustituto de autorización. Entrar en 09 abre un menú sin
ejecutar herramientas ni heredar el objetivo de sesión.

- [Uso, permisos y matriz de conservación](USE.md).
- [Todas las opciones y herramientas 00–13](../../docs/MENU-OPCIONES.md).
- [Estado y verificación sintética](../../docs/AUTOMATION-2026-11-13.md).
- [Contrato Docker estático](docker/README.md): no es un sandbox.

Desde el directorio del framework, solo preview:

```bash
python3 -I 09_Automation/python/orchestrator.py --target 192.0.2.1
```

La ejecución exige permisos separados y dependencias presentes; leer USE antes
de añadir flags. PowerShell no está probado en Windows y Docker no se ha
construido ni ejecutado. Archivos conservados no acreditan integración operacional.

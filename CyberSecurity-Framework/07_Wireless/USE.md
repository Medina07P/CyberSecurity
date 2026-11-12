# Uso del menú de mantenimiento de 07

Desde el menú principal del gestor, entra en **07_Wireless**:

1. Elige **1** para comprobar herramientas locales. Solo consulta `command -v`;
   no ejecuta los binarios ni instala los que falten. Una herramienta disponible
   no certifica hardware, permisos ni funcionamiento operacional.
2. Elige **2** para leer la guía y sus límites. No lee capturas ni valida evidencia.
3. Elige **11** si necesitas consultar la lista original de diez scripts. Abrir
   la lista no los ejecuta; se conserva la selección y confirmaciones habituales
   del gestor. Las operaciones existentes siguen requiriendo autorización y una
   revisión específica, no forman parte de la comprobación local.
4. Elige **0** para volver. EOF también retorna sin iniciar acciones; una opción
   inválida muestra un aviso y mantiene el menú.

Tras las opciones 1 y 2, el gestor pausa antes de volver al menú. Ninguna de
ellas eleva privilegios, cambia interfaces o servicios ni transmite por radio.

## Qué no demuestra este mantenimiento

`wifi_handshake.sh` **imprime una guía**, no captura ni verifica automáticamente
un handshake. No se ofrece aquí una receta de captura, desautenticación o
craqueo. Las diez entradas originales, incluido `run_all_wireless.sh`, permanecen
intactas; conservar su acceso no acredita su integración operacional.

No ejecutes hojas ni el flujo completo como prueba rápida. La suite
`tests/run_wireless_maintenance.sh` verifica UI con fixtures y fronteras simuladas,
no una radio real ni capturas válidas. Las regresiones antiguas se ejecutan solo
en copias limpias con configuración sintética, nunca sobre evidencia real.

Inventario y límites: [README.md](README.md). Resultados y estado heredado:
[WIRELESS-MANTENIMIENTO-2026-11-11.md](../../docs/WIRELESS-MANTENIMIENTO-2026-11-11.md).

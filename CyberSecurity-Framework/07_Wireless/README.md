# 07_Wireless — mantenimiento

El gestor abre un menú de mantenimiento. No constituye una auditoría inalámbrica
ni la implementación del plan operacional integral de 07.

## Menú del gestor

| Opción | Comportamiento |
|---|---|
| `1` | Comprueba disponibilidad local mediante `command -v`, sin ejecutar herramientas. |
| `2` | Explica la guía y los límites de mantenimiento, sin leer capturas. |
| `11` | Abre la lista original de diez scripts; no los ejecuta automáticamente. |
| `0` | Vuelve al menú principal; EOF también retorna sin despachar acciones. |

La comprobación consulta `sudo`, `ip`, `iw`, `airodump-ng`, `aireplay-ng`,
`aircrack-ng`, `hcitool`, `bluetoothctl`, `sdptool` y `gatttool`. No instala
dependencias, eleva privilegios, cambia interfaces o servicios ni transmite
por radio. Disponibilidad en PATH **no acredita** adaptador compatible,
permisos, funcionamiento operacional ni auditoría realizada.

## Lista original conservada

- `bluetooth/bt_discover.sh`
- `bluetooth/bt_scan.sh`
- `run_all_wireless.sh`
- `scripts/channel_hopper.sh`
- `scripts/interface_manager.sh`
- `wifi/wifi_crack.sh`
- `wifi/wifi_deauth.sh`
- `wifi/wifi_handshake.sh`
- `wifi/wifi_monitor.sh`
- `wifi/wifi_scan.sh`

La opción 11 mantiene la selección y confirmaciones del listado genérico del
gestor. Esa frontera permite acceder a operaciones existentes: **no convierte
las hojas ni el flujo completo en comprobaciones pasivas**. Su uso exige
alcance autorizado y revisión operacional específica; no usarlos como smoke test.

`wifi_handshake.sh` imprime una guía: **no captura ni verifica un handshake
automáticamente**. Texto de guía o presencia de archivos no demuestra captura
válida. Las diez fuentes se conservan sin modificación ni ejecución durante
este mantenimiento; no se declara integrado ni verificado su flujo operacional.

`captures/` contiene datos generados ignorados por Git; no se leen ni se limpian
como parte de esta entrega. Navegación: [USE.md](USE.md). Alcance y regresión:
[WIRELESS-MANTENIMIENTO-2026-11-11.md](../../docs/WIRELESS-MANTENIMIENTO-2026-11-11.md).

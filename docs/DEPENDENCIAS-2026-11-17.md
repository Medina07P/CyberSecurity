# Dependencias (tecla `D`)

El gestor (`cyber_framework.sh`) tiene una tecla nueva, `D`, que reúne en un
solo sitio la comprobación de herramientas que antes vivía repartida por
módulo (`exploitation_check_tools`, `scanners_check_tools`,
`wireless_check_tools`, `postexploitation_check_tools`,
`enumeration_check_tools`, la opción 1 de `evidence_menu`, y
`08_Forensics/requirements.sh --check`).

## Qué muestra

Al entrar a `D` se ve, agrupado por módulo, el estado ✓/✗ de cada binario que
el framework ya comprueba en algún sitio, más `rustscan`, `volatility3`,
`foremost` y `nmap-vulners` (los huecos que documenta `AGENTS.md`) y
`zaproxy` (pedido explícitamente para cuando exista un escáner OWASP ZAP —
ese escáner en sí **no** está construido todavía; esta tecla solo lo lista).

Un binario que varios módulos comprueban a la vez (`nmap`, `python3`,
`curl`...) aparece **una sola vez**, bajo el primer módulo que lo comprueba.

## Qué instala, y qué no

Solo `apt`. Nunca `pip`, `cargo`, `go install`, Docker ni un binario bajado a
mano. Seis entradas no tienen paquete apt y por eso **nunca** aparecen en la
lista de instalación, aunque se muestren como `✗` en el estado: `sdptool`,
`gatttool`, `avml`, `lime`, `volatility` (v2 clásico — reemplazado por
`volatility3`, que sí se instala) y `nmap-vulners` (no es un binario: es un
script NSE que se clona a mano a `/usr/share/nmap/scripts/`).

Elegir "Instalar dependencias" numera solo lo que falta **y** tiene paquete
apt; se eligen números sueltos, varios separados por espacio, o `todas`.
Después de elegir hay **una sola confirmación** (escribir `instalar`
literalmente) y **una sola** llamada a `sudo apt-get install -y <paquetes>`.
Cualquier otra respuesta, un número fuera de rango, `0`/`!`, o Ctrl-D
cancelan sin instalar nada.

## Duplicación conocida con `08_Forensics/requirements.sh`

`08_Forensics/requirements.sh --install` ya instala de verdad seis paquetes
forenses (confirmación `INSTALAR_DEPENDENCIAS`, en mayúsculas) y cinco de
ellos (`autopsy`, `foremost`, `scalpel`, `tcpdump`, `wireshark`) también
están en la tabla de `D`. Es intencional: `D` es un camino rápido e
independiente, pensado por el usuario para no depender de otros flujos del
framework. `apt-get install` sobre un paquete ya instalado no hace nada, así
que no hay conflicto real entre los dos caminos — solo dos frases de
confirmación distintas si alguna vez se usan ambos para lo mismo.

## Diseño e implementación

- Diseño completo: `docs/superpowers/specs/2026-11-17-dependencias-design.md`
- Plan de implementación: `docs/superpowers/plans/2026-11-17-dependencias.md`
- Código: `00_Config/lib/dependencies.bash` (datos y las cuatro funciones:
  `dependencies_binary_ok`, `dependencies_status`,
  `dependencies_missing_with_package`, `dependencies_install`) y
  `dependencies_menu()` en `cyber_framework.sh` (navegación, igual patrón que
  `keys_menu()`/tecla `K`).
- Pruebas: `tests/run_dependencies.sh` (aislado, sin red ni `sudo`/`apt-get`
  reales) y dos casos nuevos en `tests/run_smoke.sh`.

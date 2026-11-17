# Diseño: comprobación e instalación de dependencias (tecla `D`)

**Fecha:** 2026-11-17
**Estado:** propuesto, pendiente de aprobación
**Alcance:** solo la opción de dependencias (checkbox 2 de la nota de memoria
`zap-deps-integration-2026-11-15`). La integración de OWASP ZAP como escáner
sigue sin aprobar y no se toca aquí; `zaproxy` entra en la tabla de abajo
porque el usuario lo pidió explícitamente ahora, aunque el escáner que lo usará
todavía no exista.

## Intención y por qué

Hoy cada módulo comprueba sus propias herramientas por separado
(`exploitation_check_tools`, `scanners_check_tools`, `wireless_check_tools`,
`postexploitation_check_tools`, `enumeration_check_tools`, la opción 1 de
`evidence_menu`, `08_Forensics/requirements.sh --check`) y ninguno instala
nada. El usuario quiere un sitio único para ver qué falta en todo el
framework y, si quiere, instalarlo con una sola confirmación — sin tener que
entrar módulo por módulo ni teclear `apt-get install` él mismo.

## Goals

- Una tecla nueva en el menú principal (`D`) que: (a) liste el estado
  (✓/✗) de todas las herramientas que el framework ya comprueba en algún
  módulo, agrupadas por módulo; (b) ofrezca instalar las que falten y
  tengan paquete apt conocido, con **una sola confirmación** y **un solo**
  `sudo apt-get install -y <lista>`.
- Reusar el patrón ya existente (`K` → `keys_menu`): función en una librería
  nueva `00_Config/lib/dependencies.bash`, sourceada por `cyber_framework.sh`,
  dispatch por letra en el bucle principal.
- Tratar con honestidad los casos donde `comando → paquete apt` no es 1:1,
  o donde no hay paquete apt en absoluto.

## Non-goals

- No sustituye las comprobaciones locales de cada módulo (`exploitation_check_tools`
  y las demás siguen como están); esta es una vista agregada adicional, no un
  reemplazo.
- No se coordina con `08_Forensics/requirements.sh --install`, que ya instala
  de verdad (`sudo apt install -y volatility autopsy foremost scalpel tcpdump
  wireshark`, confirmación `INSTALAR_DEPENDENCIAS`) y comparte 5 de sus 6
  paquetes con la tabla nueva. Es una **duplicación conocida y aceptada**:
  decisión explícita del usuario de mantener `D` como camino independiente y
  rápido, no una omisión. Ambos caminos seguirán pudiendo instalar los mismos
  paquetes por separado; `apt-get install` sobre un paquete ya instalado es
  no-op, así que no hay riesgo de conflicto, solo de confirmaciones distintas
  (`instalar` en `D` vs `INSTALAR_DEPENDENCIAS` en `requirements.sh`).
- No instala nada por `pip`, `cargo`, `go install`, Docker, binarios de GitHub
  ni similares. Solo `apt`. Lo que no tenga paquete apt se reporta como
  "sin instalación automática aquí", nunca se intenta instalar por otra vía.
- No gestiona `sudo` ni credenciales: si `sudo apt-get install` pide contraseña,
  la pide el propio `sudo` en la terminal, igual que cualquier otro comando
  manual. El menú no cachea ni agiliza eso.
- No valida versiones, actualiza `apt update` por su cuenta, ni resuelve
  dependencias rotas de apt — eso es trabajo de apt mismo.
- No cubre `volatility` (v2 clásico): ya no tiene paquete apt en Kali (solo
  `volatility3` lo tiene); se documenta como "sin instalación automática",
  igual que `avml` y `lime` (ninguno de los tres existe como paquete apt).

## Anti-goals

- Que la opción dé una falsa sensación de "ya quedó instalado todo" cuando en
  realidad quedaron fuera herramientas sin paquete apt. El menú debe separar
  explícitamente "faltan y se pueden instalar por apt" de "faltan y no hay
  instalación automática", nunca mezclarlas en una sola lista de "pendientes".
- Que la instalación masiva incluya paquetes que el usuario no pidió revisar
  (p. ej. tirar de todo un metapaquete tipo `kali-linux-headless`). Se instala
  binario por binario, por su paquete específico.

## Constraints

- Mismo patrón de estilo que `keys_menu` (colores `CYAN/BOLD/GREEN/DIM/RED`,
  `clear_screen`, `pause`, letra de vuelta `0`).
- La tecla `D` está libre (comprobado: no aparece en el `case` del bucle
  principal de `cyber_framework.sh`).
- Nada de `set -e`; cada apt install se reporta con su propio código de salida,
  como el resto del framework hace con `errores.log`.
- El framework no debe hardcodear rutas de `$HOME`; esto no aplica aquí porque
  no hay rutas nuevas, solo invocaciones de `command -v` y `apt-get`.
- Las pruebas nuevas (`tests/run_dependencies.sh` o similar) deben poder
  ejecutarse sin red y sin `sudo` real: el "instalar" se cubre con un `apt-get`
  fake inyectado por `PATH`, nunca con una instalación real durante tests.

## Approaches consideradas

Solo hay una forma sensata de construir esto dentro de la arquitectura
existente — las alternativas reales son de *alcance*, no de arquitectura:

1. **(Elegida) Librería nueva + tecla `D`, instalación vía mapa binario→paquete,
   confirmación única.** Sigue el patrón `K`/`keys_menu` al pie de la letra;
   reusa `command -v` que cada módulo ya usa; una sola lista de paquetes apt en
   un único comando de instalación.
2. **Delegar en cada módulo (sin vista agregada).** Descartada: es justo lo que
   ya existe y es lo que el usuario pidió cambiar — no hay un sitio único.
3. **Un script Python aparte (como `api_keys.py`)** en vez de una librería
   `.bash`. Descartada: no hay estado persistente que gestionar (a diferencia
   del registro de claves API, que vive en un YAML con seis destinos); esto es
   puro `command -v` + `apt-get`, que no necesita Python, y mantenerlo en bash
   es consistente con el resto de `00_Config/lib/*.bash`.

## Decisiones de diseño (del usuario, en esta conversación)

- Opción con instalación (la nº3 que propuse), no solo un listado de estado.
- Incluir `zaproxy` en la tabla ya mismo, aunque el escáner ZAP en sí no esté
  aprobado/construido todavía.
- La instalación **no es "todo lo que falte" de una vez**: `D` muestra el
  estado (instalado/no) y, en una opción separada, una lista numerada de lo
  que falta para que el usuario elija cuáles instalar — pensada para ser
  rápida e independiente de cualquier otro flujo del framework.
- Sobre la superposición con `08_Forensics/requirements.sh --install`
  (pregunta nº3 del builder check): caminos independientes, sin coordinarse
  entre sí (opción *a*; ver "Non-goals" y la nota de duplicación conocida).

## Decisiones de diseño (mías, a confirmar como parte de este doc)

### Tabla binario → paquete apt

Unión de todo lo que los módulos ya comprueban (`exploitation_menu.bash`,
`scanners_menu.bash`, `wireless_menu.bash`, `postexploitation_menu.bash`,
`enumeration_menu.bash`, `evidence_menu.bash`, `08_Forensics/requirements.sh`)
más los huecos de `AGENTS.md` (`rustscan`, `volatility3`, `foremost`,
`nmap-vulners`) más `zaproxy`. Verificado en este Kali con `apt-cache policy`
y, donde hacía falta, `dpkg -S` sobre el binario ya instalado:

| Binario | Paquete apt | Nota |
|---|---|---|
| nmap | nmap | |
| hydra | hydra | |
| sqlmap | sqlmap | |
| curl | curl | |
| ffuf | ffuf | |
| python3 | python3 | |
| nc | netcat-traditional | confirmado por alternatives en este Kali |
| iwlist | wireless-tools | |
| ip | iproute2 | |
| masscan | masscan | |
| rustscan | rustscan | hueco de AGENTS.md, sí tiene paquete |
| nikto | nikto | |
| nuclei | nuclei | |
| burpsuite | burpsuite | |
| sudo | sudo | |
| iw | iw | |
| airodump-ng / aireplay-ng / aircrack-ng | aircrack-ng | un paquete, tres binarios |
| hcitool / bluetoothctl | bluez | |
| sdptool / gatttool | — | **sin paquete apt en este Kali** (`apt-cache policy` vacío); se reporta "sin instalación automática" |
| find | findutils | normalmente ya presente en cualquier Debian/Kali |
| ssh | openssh-client | |
| crontab | cron | |
| getcap | libcap2-bin | |
| scrot | scrot | |
| import | imagemagick | |
| gnome-screenshot | gnome-screenshot | |
| wget | wget | |
| ftp | ftp | |
| ldapsearch | ldap-utils | |
| rpcclient / smbclient | smbclient | confirmado por `dpkg -S` en este Kali |
| enum4linux | enum4linux | |
| mysql | mariadb-client | confirmado por `dpkg -S` (`mariadb-client-core` lo provee; se instala con el metapaquete `mariadb-client`) |
| psql | postgresql-client | confirmado por `dpkg -S` |
| whatweb | whatweb | |
| timeout | coreutils | normalmente ya presente |
| cutycapt | cutycapt | |
| tcpdump | tcpdump | |
| wireshark | wireshark | binario de captura con GUI; instalar no da permisos de captura sin grupo `wireshark` |
| volatility3 | volatility3 | hueco de AGENTS.md, sí tiene paquete |
| autopsy | autopsy | |
| foremost | foremost | hueco de AGENTS.md, sí tiene paquete |
| scalpel | scalpel | |
| avml | — | **sin paquete apt**; binario de GitHub (Microsoft), no se instala aquí |
| lime | — | **sin paquete apt**; módulo de kernel que se compila, no se instala aquí |
| dd | coreutils | siempre presente, se incluye solo para que el estado no lo muestre como "falta" |
| volatility (v2 clásico) | — | **sin paquete apt** en este Kali (reemplazado por `volatility3`); se documenta, no se instala |
| nmap-vulners | — | **no es un binario**: es un script NSE que se clona a mano a `/usr/share/nmap/scripts/`; se reporta como "sin instalación automática (requiere clonar el repo manualmente)" |
| zaproxy | zaproxy | pedido explícito del usuario; aún sin escáner que lo use |

Los "sin paquete apt" (`sdptool`/`gatttool`, `avml`, `lime`, `volatility` v2,
`nmap-vulners`) aparecen en el listado de estado como ausentes pero **nunca**
entran en la lista de instalación ni en el `apt-get install`; se les añade una
línea con el motivo (ya redactada en la tabla).

### Estructura de la librería nueva

`00_Config/lib/dependencies.bash`:

- `DEPENDENCIES_MAP` — array asociativo bash `binario → paquete` con las filas
  de arriba que sí tienen paquete.
- `DEPENDENCIES_NO_APT` — array asociativo `binario → motivo` con las cinco
  filas sin paquete (`sdptool`, `gatttool`, `avml`, `lime`, `volatility` v2,
  `nmap-vulners`).
- `DEPENDENCIES_GROUPS` — el agrupamiento visual, fijo en el código: cada
  binario aparece **una sola vez**, bajo el primer módulo de la lista de
  abajo que lo comprueba (orden fijo: Scanners, Exploitation, Enumeration,
  Postexploitation, Wireless, Evidence, Forensics). `zaproxy`, `volatility3`
  y `nmap-vulners` — que hoy ningún módulo comprueba — van en un grupo nuevo
  "Dependencias adicionales". Esto resuelve que `nmap`/`python3`/`curl`/etc.
  los comprueben varios módulos a la vez: solo se listan una vez.
- `dependencies_check_one(binario)` — la comprobación real por binario. Para
  todos excepto `nmap-vulners` es `command -v "$binario"`. Para
  `nmap-vulners`, que no es un binario sino un script NSE, es
  `[[ -f "${NMAP_VULNERS_PATH:-/usr/share/nmap/scripts/nmap-vulners.nse}" ]]`
  — así si alguien lo clona a mano puede pasar a ✓, en vez de quedar fijo en
  ✗ como un `command -v` de un comando que no existe nunca haría; la variable
  de entorno permite a los tests apuntar a una ruta temporal sin tocar la
  real, igual que `SESSION_FILE`/`SESSION_SCOPE_FILE` en `session.bash`.
- `dependencies_status()` — recorre `DEPENDENCIES_GROUPS` llamando a
  `dependencies_check_one` por cada binario, imprime ✓/✗ agrupado, solo
  lectura (nunca llama a `apt-get`).
- `dependencies_list_missing()` — imprime, numerada, la lista de binarios
  ausentes que sí están en `DEPENDENCIES_MAP` (los de `DEPENDENCIES_NO_APT`
  se muestran en el estado pero nunca en esta lista numerada). Dos binarios
  que comparten paquete (p. ej. `airodump-ng`/`aireplay-ng`/`aircrack-ng`) se
  colapsan en una sola entrada de la lista, mostrando el paquete.
- `dependencies_install()` — pide al usuario los números a instalar (acepta
  varios separados por espacio, o `todas`), construye la lista de paquetes
  deduplicada de **solo lo elegido**, la muestra, pide confirmación explícita
  (`escriba 'instalar' para continuar`, igual de explícito que otras
  confirmaciones peligrosas del framework), y si se confirma ejecuta **un
  solo** `sudo apt-get install -y "${paquetes[@]}"` con la selección,
  propagando su código de salida y su `stderr` tal cual (sin `2>/dev/null`).
  Si no hay nada ausente con paquete apt, lo dice y no pide nada.

### Menú (`dependencies_menu` en `cyber_framework.sh`, tecla `D`)

Mismo patrón visual que `keys_menu`:

```
━━━ DEPENDENCIAS ━━━

03_Scanners:
  ✓ nmap          ✓ nikto          ✗ rustscan
  ...
08_Forensics:
  ✗ avml (sin instalación automática: binario de GitHub, no hay paquete apt)
  ...
Dependencias adicionales:
  ✗ zaproxy       ✗ volatility3    ✗ nmap-vulners (sin instalación automática: script NSE, se clona a mano)

1) Instalar dependencias (elegir de la lista)
0) Volver al menú principal

➜ Elige una opción [0-1]:
```

La opción `1` llama primero a `dependencies_list_missing` (lista numerada,
solo lo que tiene paquete apt) y luego a `dependencies_install`, que pide qué
números instalar antes de pedir la confirmación final. El estado (✓/✗) ya se
ve siempre al entrar a `D`, sin submenú aparte — por eso no hay una opción
"2) ver estado" separada: es lo primero que se imprime.

### Pruebas

`tests/run_dependencies.sh` nuevo, aislado como el resto de `tests/`. El
aislamiento sigue el patrón ya probado de `tests/run_forensics.sh` (líneas
~113-132, el que cubre `08_Forensics/requirements.sh --install`): un `PATH`
**cerrado** que contiene únicamente un directorio `bin/` de stubs, con `sudo`
y `apt`/`apt-get` incluidos en esos stubs como "denegado" (`exit 99` si se
invocan sin pasar por el stub esperado). Un simple "prepender un `apt-get`
falso al `PATH`" no basta: en Kali/Debian el `secure_path` por defecto de
`sudo` descarta el `PATH` del que llama al ejecutar el comando, así que
`sudo apt-get install` podría resolver el `apt-get` real por su propio
`secure_path` aunque el test haya puesto uno falso delante. Por eso se
necesita el `PATH` cerrado, no el prepend.

- El stub de `apt-get`/`sudo` registra en un archivo la lista exacta de
  paquetes que habría instalado y devuelve un código fijo, para comprobar que
  (a) la lista nunca incluye un binario de `DEPENDENCIES_NO_APT`, (b) está
  deduplicada, (c) solo contiene lo que el test "seleccionó" por número,
  (d) la confirmación (`n`/cadena distinta de `instalar`) corta sin invocar
  el stub en absoluto.
- Un `command -v` fake (mismo `PATH` cerrado, con binarios stub presentes o
  ausentes según el caso) para probar ✓ y ✗ sin depender de lo que esté
  realmente instalado en la máquina que corre los tests.
- Caso aparte para `nmap-vulners`: el test crea y borra
  `/usr/share/nmap/scripts/nmap-vulners.nse` (o una ruta inyectable por
  variable de entorno, para no tocar la real) para comprobar que
  `dependencies_check_one` cambia de ✗ a ✓ con el archivo presente.
- Comprobación de que `dependencies_status` y `dependencies_list_missing`
  nunca invocan el stub de `apt-get`/`sudo` (solo lectura).

## Qué queda para quien implemente

- Redactar los textos exactos en español de cada línea del menú (tono igual
  al resto: directo, sin tecnicismos de proceso).
- Decidir el orden de agrupación visual (por módulo, como arriba, es la
  propuesta; si se prefiere alfabético por binario, es un cambio menor).
- Verificar en el momento de implementar si Kali cambió algún nombre de
  paquete desde este recon (`apt-cache policy` de nuevo antes de fijar la
  tabla en el código, por si el repo se movió).

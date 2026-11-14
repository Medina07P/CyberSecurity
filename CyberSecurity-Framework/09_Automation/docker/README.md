# Docker: fuentes permitidas y shell sin acciones

Este contrato requiere **BuildKit con soporte de Dockerfile-specific ignore**:
`Dockerfile.dockerignore` junto al Dockerfile. El contexto de Compose es el
framework (`../..`), y el Dockerfile es `09_Automation/docker/Dockerfile`.
No usar un builder antiguo que omita ese filtro ni sustituirlo por `COPY . .`.
No se ha ejecutado Docker, construido la imagen ni validado paquetes en esta tarea.

El filtro deniega todo y reabre únicamente nombres exactos de fuentes y los dos
workflows de 09. Cada ancestro reabierto vuelve a denegar sus descendientes antes
de las excepciones exactas: permitir un directorio sin esa denegación incluiría
también archivos privados. No hay globs de extensiones. La lista incluye el
paquete automation, las entradas de 09 y sus dependencias de fuentes para OSINT,
escáneres, SSH/SMB, SQLmap y el motor de informes. No incluye gestor completo,
tests, configuración, wordlists, claves, sesiones, perfiles, resultados o logs.
Para añadir una fuente, revisar su nombre versionado y sus dependencias; nunca
generar excepciones recorriendo datos del checkout. El contrato usa YAML seguro
y candidatos sintéticos; no ejecutarlo en host. Forma parte de la selección
interior revisada descrita en [el aislador test-only](../../../docs/AUTOMATION-TEST-ISOLATION-2026-11-13.md).
La guía nueva está fuera del contexto framework; no se amplía el filtro para
admitirla, ni para admitir helpers/runtime/manifiestos de pruebas. La guía USE
continúa admitida por su nombre exacto; ningún glob nuevo ni fuente privada.

El default abre solo Bash sin perfiles ni archivos de inicio, como `toolkit`, con
home privado. No inicia herramientas ni instala nada en runtime. Compose no monta
código ni datos, no expone el socket Docker, no usa red/PID/IPC del host y elimina
capacidades, sin privilegios nuevos. La red bridge predeterminada **no bloquea
salidas de red**. No hay overrides de servicio ni volúmenes predeterminados;
revisar cualquier override externo antes de usarlo.

Los datos nuevos se guardan en la **capa del contenedor** (framework bajo el home,
scans junto a él); se pierden al eliminarlo. Exportar de forma deliberada los
artefactos necesarios antes de eliminarlo; no resolver persistencia montando el
repositorio, credenciales o el socket del host. La imagen no trae configuración
local ni credenciales: las acciones que las necesiten requieren preparación
explícita y autorización, no se deben inventar secretos o configuración de alcance.

Se conserva Kali rolling y la lista previa de herramientas, deduplicando Hydra,
usando `netcat-openbsd` y paquetes Python apt (`python3-yaml/requests/bs4/scapy/shodan`).
No se promete que todos los backends estén instalados o funcionen; raw sockets,
captura, SO y hardware pueden requerir permisos que este default **no concede**.
No elevar privilegios automáticamente para hacerlos funcionar. Rolling y sus
paquetes no están fijados: este cambio no acredita reproducibilidad del build.
Un contenedor **no es un sandbox de seguridad**, ni autorización para contactar
destinos. Solo se ha verificado el contrato estático, no compatibilidad operacional.

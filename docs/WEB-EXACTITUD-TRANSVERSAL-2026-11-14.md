# Exactitud web — cierre acotado

Plan: `docs/superpowers/plans/2026-11-14-cross-module-web.md`.
Implementación revisada: `af5a4de`. Revisión independiente de requisitos y calidad
aprobada dentro del alcance sintético; no cierre global.

## Resultado

- Composición simultánea desde captura original: target/cuerpo coherentes,
  overrides literales, rechazo de campos ambiguos y conservación de números JSON
  sin redondeo. Nuevas interfaces no alteran las sustituciones individuales.
- Login capturado transmite cada candidato real sin restaurar la contraseña
  original. Esquema seleccionado localmente; sin sondeos ni descargas previas
  al consentimiento. Modo manual conserva bytes literales, incluso marcadores,
  ampersands y cuerpos que empiezan por `@`, sin adoptar archivos del operador.
- Rate-limit:403 sin señal explícita corta inmediatamente como NO DETERMINADO;
  conserva precedencia de429/503, Retry-After y cuota agotada, mínimo temporal y
  límite200 con `wrong-N`. No se añaden intentos ni reintentos.
- curl no expande URL-globs en los tres transportes. Datos por stdin; fallos del
  productor o consumidor detienen evaluación y conservan el intento y parciales.
- Documentación y contratos alineados; controles SQLmap y empaquetado11 intactos.

## Verificación fresca del controlador

Launcher fijo `python3 -I -B CyberSecurity-Framework/tests/automation_sandbox_launch.py`,
comandos separados y autorizados después de revisión estática del SHA indicado:

| Selector | Resultado | Recibos bajo `/tmp/opencode/` |
|---|---|---|
|`--cross-web`|rc0,65units+7WEB,0fallos/errores/omitidos|`automation-isolated-c260d9abcbcb4ba3afb1cb6aada1a68f/evidence/`|
|`--cross-consent`|rc0,65units+9consent,0fallos/errores/omitidos|`automation-isolated-83b88c159ced4d06bbe7b79a0d8c38f2/evidence/`|
|`--suite`|rc0,65units+179integración,0fallos/errores,1SKIPpwsh|`automation-isolated-f75d3ff67f88429db03cd5f28fe3b658/evidence/`|

Siete workers WEB con ABI7 observado: cinco grants exactos, dos puros sin permiso
destructivo. Consent9 e inventario histórico25 separados. Pruebas solo en copias
allowlist y scratch nuevo, configuración y wordlists sintéticas, curl obligatorio
doble sin sockets ni fallback. Rojos históricos y parciales se preservan; no
atribuir al código final los conteos de versiones anteriores.

Revisión/evidencia y decisiones completas:
`.superpowers/sdd/2026-11-14-cross-module-web/{progress,final-evidence-review}.md`.

## Decisiones y límites

Se añadieron siete casos completos antes del primer RED, sin esconder fallos de
tareas posteriores. `/usr/bin/rm` y su cierre exacto libc/loader se incorporaron
con autorización expresa y revisión de procedencia: solo temporales sintéticos
nuevos, no borrado de artefactos históricos. Se corrigieron también los menores.
Los defectos manuales heredados se detectaron en recibos reales sintéticos y se
repararon con oráculos reforzados antes del cierre; no son nuevas técnicas.

Respuestas diferenciales son heurística, no prueba de credenciales válidas.
No auditoría real, compatibilidad universal de herramientas, Windows/Docker,
custodia legal, host/kernel hostil ni garantía realtime/cgroups por árbol. ABI3
no cubre toda metadata/ioctl. No se ejecutaron suites heredadas sobre este checkout.
No merge/push, instalaciones ni limpieza global. Planes local y menores/cierre
siguen pendientes; worktree, fuentes, fixtures y todos los logs se conservan.

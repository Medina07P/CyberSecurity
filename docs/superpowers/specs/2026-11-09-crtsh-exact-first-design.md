# crt.sh: consulta exacta antes de búsqueda ampliada

Estado: diseño corto aprobado en conversación («Sí, hazlo»).

## Objetivo
No perder nombres de certificados cuando la búsqueda ampliada de crt.sh falla.
La comprobación real encontró que una consulta exacta podía responder mientras
la ampliada devolvía 502 o agotaba el plazo. No registrar objetivos reales aquí.

## Alternativas y decisión
- Subir plazos: empeora espera sin resolver la dependencia; descartada.
- Consulta exacta primero, ampliada después, conservando evidencia parcial:
  propuesta elegida y aprobada por el usuario.

## Contrato
- `collect_certificates` mantiene su firma y devuelve la unión única de nombres
  observados. `run.results` registra `crtsh_exact` y `crtsh_wildcard` por separado.
- Consulta exacta `q=dominio`, seguida por `q=%.dominio`; no repetir en run_all.
- Filtrar nombres ajenos, comodines y nombres DNS inválidos; no contar certificados
  como subdominios activos. DNS recibe nombres únicos incluso si alguna consulta
  de certificados falló. Cada evidencia conserva procedencia de la consulta.
- Mantener 15 s absolutos/solicitud, 120 s/fuente, 10 solicitudes API totales por
  ejecución incluidos reintentos. Ambas consultas comparten presupuesto `crtsh`.
- Un 502 o timeout de consulta no bloquea la otra consulta independiente; un
  bloqueo HTTP 401/403 o 429/503 persistente sigue deteniendo todo el proveedor.
  No reintentar una consulta fallida en bucle ni reiniciar presupuestos.
- Fallo de una consulta implica salida parcial/código 1 aunque se conserven
  nombres o el DNS tenga éxito. Ambas completadas vacías es código 0, no fallo.
- Sin nuevos proveedores, claves, diccionarios ni cambios de parámetros del menú.

## Seguridad y verificación
Tests de orden, union/deduplicación, errores parciales, frenos, presupuestos,
JSON inválido, dominios ajenos y DNS sobre nombres parciales. Fixtures sintéticos;
regresión completa solo en worktree/clon limpio, nunca sobre evidencias reales.
No tocar scope.yaml ni los resultados existentes. Commits locales y merge a
develop según el flujo nativo ya elegido por el usuario; no push.

Se detectó además que las nuevas carpetas de ejecución OSINT no estaban todas
cubiertas por `.gitignore` (solo había extensiones sueltas). Añadir una regla
limitada a `01_OSINT/*/osint_*/` y probarla para evitar versionar datos reales;
no mover ni eliminar resultados.

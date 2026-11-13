# Contrato del operador

Los wrappers se autolocalizan; no requieren arrancar desde el módulo. Solo el
archivo de importación relativo se interpreta desde el cwd del llamador.
Ejemplos offline con un archivo sintético local `sample evidence.txt`:

```bash
./evidence_manager.sh --add screenshot "sample evidence.txt" "Fixture, no PNG real"
./evidence_manager.sh --add pcap "sample evidence.txt" "Fixture, no PCAP real"
./evidence_manager.sh --add credential "sample evidence.txt" "Credencial ficticia"
./evidence_manager.sh --add finding "sample evidence.txt" "Hallazgo ficticio"
./evidence_manager.sh --add proof "sample evidence.txt" "Prueba ficticia" --target 192.0.2.10
./evidence_manager.sh --help
./auto_capture.sh --help
./run_all_evidence.sh --offline
```

Los cinco tipos de importación no validan semánticamente el contenido: el tipo es
clasificación del operador. La validación limitada de PNG/PCAP/Nmap corresponde
a adquisición, no a `--add`. La descripción es opcional; `--target ETIQUETA`
es opcional y explícito, nunca se adopta la sesión ni se atribuye un hallazgo
automáticamente. Las etiquetas no modifican scope, targets ni sesión.

## Adquisición explícita (no ejecutar como prueba de humo)

`auto_capture.sh` requiere al menos una selección. `--web URL`,
`--traffic HOST --interface IFACE` y `--scan HOST --scan-profile PERFIL`
requieren además `--authorize-network`. Es una afirmación del operador, no una
barrera de alcance; compruebe autorización antes. `HOST` es una IP/dominio único,
no CIDR, rango, opciones ni filtro libre. Las acciones son secuenciales.

| Acción | Contrato y límites |
|---|---|
| `--web URL` | HTTP/HTTPS explícito con puerto/ruta; sin credenciales, fragmentos ni controles. cutycapt, deadline 60 s. Solo firma PNG y contenido adicional, no decodificación ni validación visual. No se confinan redirecciones/subrecursos: deben estar autorizados también. |
| `--traffic HOST --interface IFACE` | tcpdump sin sudo. `--duration` 1–300 s (10 por defecto), `--packet-limit` 1–10000 (100 por defecto), solo para tráfico. Cierre al intervalo y reap; valida cabecera y registros PCAP, no interpreta protocolos. Un PCAP válido vacío se etiqueta `SIN TRÁFICO`, no fallo del objetivo. |
| `--scan HOST --scan-profile basic` | TCP connect, 100 puertos, sin NSE/versionado; deadline 120 s. |
| `--scan HOST --scan-profile full` | TCP connect, `-sV -p-`, sin tasa agresiva implícita; deadline 1800 s. Coste e intrusividad mayores. |
| `--system` | Sin red: UTC, usuario, hostname y uname del **OPERADOR**, nunca del objetivo; sin secretos del entorno. |

Nmap exige rc satisfactorio y marcador final coherente; esto no valida la
exactitud del escaneo ni convierte su salida en hallazgo confirmado.
No hay instalación automática ni fallback a otra herramienta. Dependencia
ausente, salida inválida, timeout no previsto o paso parcial dan rc 1;
otras acciones independientes pueden continuar. Cada ejecución deja
`logs/runs/<id>/run.json` y stdout/stderr privados; solo éxitos publican registros.

El supervisor usa grupos propios y espera hijos/descendientes antes de retornar;
INT/TERM interrumpen sin publicar éxito del paso, terminan/escalan procesos propios
y retornan 130/143. No usa el contrato de montajes de 08. Un deadline limita
la herramienta; la terminación supervisada añade hasta 2 s de gracia TERM
(tráfico: INT 2 s, luego TERM 2 s), después KILL y espera de reap sin plazo.
Es supervisión Linux con subreaper, no aislamiento de backends hostiles capaces
de escapar de su grupo mediante setsid/setpgid.
La importación difiere INT/TERM solo durante los traspasos breves de identidad
de archivos/reserva/publicación, no durante la copia en streaming. Tras señal,
las acciones siguientes quedan `not-run`; cleanup no sustituye la interrupción
por un fallo ordinario y solo retira entradas cuya identidad sigue siendo propia.
Un reemplazo ajeno o un error persistente del sistema de archivos puede impedir
retirar una reserva: no se borra material ajeno para ocultarlo.

`run_all_evidence.sh --capture` acepta las selecciones anteriores y después
lista/verifica, conservando fallos/parciales. `--offline` solo lista/verifica.
La antigua invocación con un `<TARGET>` solo devuelve 2: **ya no captura**.
Esto bloquea adquisición implícita de 10 desde 99; **no repara el flujo 99 global**,
que sigue siendo peligroso y no debe usarse como smoke test.

## Retornos y menú

`--help`: 0 sin efectos; sin argumentos/CLI inválida: 2; operación completa: 0;
error operacional, verificación vacía o parcial: 1; INT/TERM: 130/143.
`--list` vacío es 0, no verificación. El menú cancela/EOF con 0 sin acciones.
Entrar o comprobar disponibilidad solo consulta `command -v`, no ejecuta backends.
No se cambia TARGET al entrar; la lista avanzada y despacho aceptan solo las
tres hojas originales, nunca código importado. `--prepared` no evita las
confirmaciones de captura/exportación. La marca de fase `done` significa
**hay evidencia reconocible**, no integridad verificada.
Incluye pares históricos `FILE: nombre` con espacios en las seis categorías,
tanto en raíz como en subdirectorios; excluye enlaces y `logs/runs/` diagnóstico.
El sondeo solo lee sidecars legacy, nunca cuerpos ni hashes de evidencias.

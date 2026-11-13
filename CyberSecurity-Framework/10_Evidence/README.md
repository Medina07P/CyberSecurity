# 10_Evidence — evidencias privadas

Las tres entradas originales se conservan; el núcleo Python estándar está en
`00_Config/lib/evidence/`. No hay instalaciones, sudo, adquisición ni red al
entrar al menú. El objetivo de sesión no autoriza ni etiqueta evidencias.

## Importar, listar, verificar y exportar

Ejemplos **offline**, desde este directorio (o invocando el wrapper por su ruta
absoluta). Cree primero un archivo sintético `sample evidence.txt` en su cwd:

```bash
./evidence_manager.sh --add proof "sample evidence.txt" "Prueba sintética" --target example.invalid
./evidence_manager.sh --list
./evidence_manager.sh --verify
./evidence_manager.sh --package muestra-readme
```

Importar copia archivos regulares sin ejecutar su contenido. Las rutas relativas
se resuelven desde el cwd del llamador; espacios se conservan si se entrecomillan.
Se rechazan enlaces, FIFO, dispositivos y directorios. Cada registro nuevo usa
un ID exclusivo con `artifact` y `evidence.json` (SHA-256, tamaño, UTC, origen,
descripción y etiqueta opcional). No reemplaza históricos ni cambia scope/sesión.

| Tipo público | Raíz |
|---|---|
| `screenshot` | `screenshots/web/` |
| `pcap` | `pcaps/traffic/` |
| `credential` | `credentials/found/` |
| `finding` | `findings/vulnerabilities/` |
| `proof` | `proofs/access/` |

Los logs internos de captura usan `logs/results/` (scan) y `logs/audit/`
(contexto OPERADOR). `logs/runs/<id>/` contiene diagnósticos privados y un ledger
validado: queda excluido del inventario exportable; no certifica evidencias.

## Estados y confidencialidad

`--list` no relee cuerpos ni verifica integridad: vacío es informativo (rc 0).
`--verify` vacío falla (rc 1); datos huérfanos, metadatos inválidos, cambios de
hash/tamaño o errores de lectura impiden un resultado global positivo.
Los `.meta` históricos se leen sin migrar: `HISTÓRICA — MD5 COINCIDE` no es
SHA-256 ni autenticidad moderna. No se rehashan para elevar su confianza.

Empaquetar exige inventario no vacío y totalmente verificado; no existe `--force`.
Publica sin reemplazar en `11_Reports/evidence/<nombre>_<id>.tar.gz`: solo datos,
metadatos originales y `manifest.json`, no código/configuración/diagnósticos.
El nombre opcional es simple, no una ruta. Un cambio durante copia aborta.
**Puede contener credenciales y NO está cifrado.** El menú pide confirmación;
la CLI explícita ya constituye la solicitud. Custodie el paquete privadamente.
Directorios nuevos 700 y archivos nuevos 600; no se reparan permisos históricos.

Los hashes/manifiestos no son firmas, cadena de custodia legal ni protección
ante un atacante que reescriba datos y metadatos. Tampoco prueban inmovilidad
frente a un origen capaz de restaurar sus metadatos durante la copia.

Consulte [USE.md](USE.md) para acciones y límites, y [FLUJO.md](FLUJO.md) para
el procedimiento. Implementación pendiente de revisión global e integración;
los stubs no acreditan compatibilidad operacional con herramientas reales.

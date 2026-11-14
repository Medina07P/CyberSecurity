# Uso de informes desde evidencias existentes

## Desde el gestor

Inicie `cyber_framework.sh` desde la raíz del framework, seleccione el host de
sesión y pulse **R**. Elija técnico, cliente o ambos. También se mantienen las
entradas del módulo **11**. Generar no vuelve a escanear, no captura tráfico,
no ejecuta scripts anteriores ni exporta secretos en un paquete automático.

Si no existe evidencia del objetivo, se generan documentos con limitaciones;
no se cambia silenciosamente a otro host. Revise «Cobertura de evidencias»,
«Candidatos» y «No evaluable» antes de entregar cualquier informe.

## CLI offline

Desde `CyberSecurity-Framework/`, seleccionando datos ya existentes:

```bash
bash 11_Reports/report_generator.sh ambos --objetivo example.invalid
bash 11_Reports/report_generator.sh tecnico --objetivo example.invalid --json
bash 11_Reports/run_all_reports.sh example.invalid

# Combinar una raíz scans externa con árboles explícitos de módulos:
python3 11_Reports/report_engine.py --objetivo example.invalid \
  --scans /trabajo/scans --fuentes /trabajo/CyberSecurity-Framework \
  --salida /trabajo/informes

# Re-renderizar un registro revisado, sin releer las fuentes:
python3 11_Reports/report_engine.py --desde-json /trabajo/informes/runs/RUN_SELECCIONADO/findings.json \
  --objetivo example.invalid --salida /trabajo/informes-revisados
```

Sin `--objetivo`, se usa `SESSION_FILE` o `00_Config/.session`. Si no hay
objetivo, retorna1 sin generar; no consulta scope, credenciales ni red.
Para un informe agregado se requiere `--todos` explícito. Los flags de tipo
`--all`/`--full` del wrapper NO autorizan agregar objetivos.

`--desde-json` valida tipos y concordancia de objetivos antes de escribir.
Sin objetivo explícito usa el del registro, no el de una sesión ajena. Un
registro multiobjetivo requiere `--todos`. La edición puede cambiar conclusiones:
el rerender no verifica cuerpos/hashes ni certifica autenticidad del registro.

## Cómo interpretar las fuentes

- Puertos, recursos accesibles, métodos HTTP y operaciones ejecutadas son
  observaciones; no equivalen a explotación.
- Masscan admite array JSON completo con IP literal, puertos enteros1–65535,
  protocolo tcp/udp y estado open. RustScan admite `Open HOST:PORT` y
  `HOST -> [PORT,PORT]`; para Open IPv6 use `[IPv6]:PORT`. Solo se retiran colores
  SGR; controles desconocidos y líneas no estructuradas quedan como límites.
  Los registros mandan sobre el nombre; no se resuelven dominios mediante DNS.
- Ambos lectores conservan el límite «finalización y actualidad no acreditadas».
  RustScan puede conservar una ejecución anterior tras fallo; Masscan puede
  dejar JSON parcial. Vacío, JSON truncado y `HOST -> []` no acreditan ausencia
  de puertos ni un último intento correcto. No se convierten banners en CVEs.
- Una referencia CVE de Nmap/Nikto es candidata, no explotación demostrada;
  Nuclei informativo es observación. En 05,
  una reflexión XSS sigue candidata; EJECUTADO no inventa un diferencial.
- 05/06 consideran el último intento por identidad; fallo, metadata inválida o
  identidad ambigua impiden resucitar éxitos. Los cuerpos de sus runs quedan privados.
- OSINT resume sus fuentes y registros; no publica emails, perfiles o texto libre
  como hallazgos. Fallo/bloqueo y vacío válido se distinguen.
- Recon solo aporta referencias de archivos, sin afirmar que sus herramientas
  terminaron bien. Capturas wireless y fuentes sin lector constan como límites.
- Forense no tiene objetivo de red implícito. Su metadata queda sin atribución;
  `--incluir-sin-objetivo` permite contexto, no valida integridad de análisis.
- 10 aporta inventario y etiqueta explícita. No se leen artefactos ni descripciones
  para deducir vulnerabilidades; el hash registrado no se recalcula aquí.

Cobertura `evaluada` significa que un lector entendió una fuente, NO que se
completara una auditoría ni que se probara su explotación. `contexto` registra
referencias; `no_evaluable` limita conclusiones; `no_soportada` necesita revisión
manual. 00 y los orquestadores de 09 no son evidencia de vulnerabilidad.

## Salidas, códigos y privacidad

Destino por defecto: `11_Reports/generated/<host>/runs/run-<UTC>-<uuid>/`.
Con `--todos` se usa `generated/_todos/runs/<id>/`, sin heredar el alcance del
host de sesión. **`REPORT_OUT_DIR`/`--salida` ahora seleccionan la raíz**, no un
directorio que se sobrescribe: se añade `runs/<id>/` dentro de esa raíz.

Técnico y cliente tienen Markdown/HTML, con registro canónico `findings.json`.
El recibo stdout `--json` incluye ID, ruta efectiva y lista `archivos`, también
`run.json`. Use ese recibo para automatizar; no suponga nombres fijos actualizados
en la raíz ni elija un HTML histórico con glob.

Cada generación, incluidas rc3 y rerenders, reserva un run exclusivo. Informes
legacy quedan intactos, sin migración, retención automática ni enlace `latest`.
El rerender crea otro run y actualiza solo la fecha de generación; no relee
scans/evidencia original. Puede comparar manualmente carpetas, pero este bloque
no incluye un comparador ni un navegador de históricos.

El recibo privado `run.json` comienza ESCRIBIENDO; solo se cierra COMPLETADO/rc0
o NO_EVALUABLE/rc3 al escribir todo el tipo solicitado. Un fallo conserva el run
incompleto propio, sin recibo stdout de éxito ni apertura de informes previos.
El estado de fase comprueba estructura/presencia de runs finales y legacy:
no valida cuerpos/hashes ni convierte un informe en auditoría completada.

0 = escrito con alguna fuente evaluable; 1 = uso/entrada/E/S; 3 = documentos
limitados sin fuentes evaluables. Los documentos con rc3 no acreditan ausencia
de riesgo. El gestor no abre un informe anterior tras rc1.

Las rutas y metadata técnicas son sensibles. No publique JSON ni informe técnico
sin revisión. El cliente omite extractos/rutas internas, pero sigue requiriendo
revisión humana. Los paquetes de 10 son acciones explícitas separadas, pueden
contener credenciales y no están cifrados. No se declara custodia legal.

Archivos nuevos600 y directorios nuevos700. Se rechazan enlaces y dependencias
especiales antes de leer/publicar; no es una defensa frente a un escritor hostil
del mismo UID que sustituya rutas durante la operación. La publicación es atómica
por archivo, no de todo el conjunto: una falla de E/S puede conservar una salida
parcial con marcador ESCRIBIENDO, sin recibo stdout ni apertura automática. No se cambian permisos de padres
preexistentes; proteja las raíces externas y revise sus exclusiones de git.

Pruebas: `bash CyberSecurity-Framework/tests/run_reports_evidence.sh` desde la
raíz del repositorio. Usa fuentes permitidas y datos sintéticos; no usar las
suites antiguas directamente sobre un checkout con datos reales.

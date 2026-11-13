# Primer uso seguro

1. Abre `CyberSecurity-Framework/cyber_framework.sh`.
2. Entra en **03 → 1**: comprueba herramientas sin enviar tráfico.
3. Con autorización para el host, usa **03 → 2**: 100 puertos TCP,
   sin NSE ni escaneo completo. Revisa el resumen antes de confirmar.
4. Para web, usa **03 → 3** y escribe la URL completa, incluyendo HTTPS,
   puerto y ruta. La sesión del gestor no determina el esquema.
5. `0` vuelve al menú anterior; `0` o `!` cancela la pregunta de objetivo.

No instales herramientas ni cambies permisos masivamente para «probar» el
módulo. No uses `run_all_scanners.sh` como smoke test: es un flujo intensivo.
El menú no usa `sudo` automáticamente.

Para comprobar las correcciones sin escáneres reales:

```bash
bash CyberSecurity-Framework/tests/run_scanners_menu.sh
```

Consulta [README.md](README.md) para requisitos, perfiles, salidas y códigos.

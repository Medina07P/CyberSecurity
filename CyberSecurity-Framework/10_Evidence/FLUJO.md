# Flujo de trabajo

1. Delimite autorización y custodia. No use 99 como humo ni adopte el objetivo
   de sesión como atribución. Entrar al menú 10, ayuda, disponibilidad y EOF
   no adquieren datos ni seleccionan TARGET.
2. Importe un archivo regular explícito (cinco tipos en README) o seleccione
   adquisición explícita según USE. Los originales no se ejecutan ni reemplazan;
   rutas con espacios se entrecomillan. No se instala ni eleva privilegios.
3. Liste sin confundir presencia con integridad; examine los diagnósticos privados
   de ejecuciones fallidas/parciales en `logs/runs/`. El sistema local es OPERADOR.
4. Verifique. SHA-256 nuevo y MD5 histórico se distinguen, sin migración automática.
   Vacío, huérfanos, corrupción o error bloquean verificación positiva/exportación.
5. Exporte solo tras éxito completo. El paquete contiene metadatos/manifiesto y
   datos verificados, no diagnósticos ni código. **No está cifrado**: puede contener
   credenciales. Confirmación en menú, solicitud explícita en CLI, nunca subida
   ni entrega automática a informes/clientes.
6. Conserve los originales, permisos y registros. Los hashes no acreditan custodia
   legal, autenticidad ni resistencia a reescritura coordinada. Pruebas con stubs
   no acreditan capturadores reales; revisión global/integración siguen pendientes.

Secuencia offline con datos sintéticos previamente importados; cualquier wrapper
se puede invocar por ruta absoluta desde otro cwd:

```bash
./evidence_manager.sh --list
./evidence_manager.sh --verify
./evidence_manager.sh --package muestra-flujo
```

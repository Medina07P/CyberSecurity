# Fichas introductorias de módulos

Estado: aprobado por el usuario el 2026-11-13; implementación pendiente.

## Intención

Ayudar a personas que no conocen pentesting a elegir el módulo adecuado sin
tener que abrir el manual. El caso que motiva el cambio es intentar usar OSINT
con la IP privada de Metasploitable sin saber que sus fuentes públicas no son
adecuadas para ese laboratorio.

## Enfoques considerados

1. **Ficha breve integrada en cada menú:** información automática sin pasos
   adicionales; requiere mantener el texto conciso. Elegido por el usuario.
2. **Pantalla introductoria separada:** permite más detalle, pero añade una
   confirmación cada vez. Descartado por esa fricción.

## Comportamiento

- Cubrir los catorce módulos, del 00 al 13.
- Mostrar la ficha bajo la cabecera del menú de entrada y antes de sus opciones.
  Mantenerla visible cuando ese menú se redibuja, sin pausas ni preguntas nuevas.
- Explicar en español sencillo: para qué sirve, qué entrada necesita, qué
  herramientas o funciones incluye y las precauciones principales.
- Indicar cuándo no aplica o se puede saltar, cuando sea relevante; en 01,
  explicar que una IP privada de laboratorio normalmente no necesita OSINT y
  orientar a reconocimiento, escáneres y enumeración.
- Distinguir consultas públicas, contacto con el objetivo, análisis local y
  acciones que pueden modificar sistemas. Entrar al menú no ejecutará pruebas.
- Verificar las descripciones contra el código actual: no presentar archivos
  presentes como capacidades operacionales ya integradas, ni presencia de una
  herramienta como instalación o disponibilidad garantizada.

## Límites y decisiones de implementación propuestas

- Cambio informativo: no cambiar validaciones, argumentos, numeración, permisos,
  confirmaciones, selección de objetivo ni ejecución de herramientas.
- No implementar ni rediseñar 09_Automation ni reabrir trabajos cerrados.
- Preservar menús especializados, archivos de configuración locales, resultados
  y evidencias; no ejecutar flujo 99, herramientas reales ni consultas externas.
- Propuesta técnica: centralizar textos en una biblioteca Bash del gestor e
  integrarlos en los puntos de dibujo de los menús, siguiendo el estilo actual.
- El detalle exhaustivo seguirá en las listas existentes y documentación; las
  fichas resumirán herramientas o funciones por grupos para no saturar la pantalla.

## Verificación prevista

Pruebas aisladas de contenido y navegación para los catorce módulos, sin red ni
configuración real; comprobar que las fichas aparecen antes de las opciones,
no añaden lecturas de entrada ni ejecutan herramientas. Validar sintaxis Bash
capturando también stderr. Las suites heredadas que alteran salidas compartidas
solo podrán ejecutarse en copia limpia y aislada.

## Fuera de alcance

Reescribir instructivos completos, corregir capacidades de los módulos, instalar
dependencias o afirmar compatibilidad operacional del framework. Sin push.

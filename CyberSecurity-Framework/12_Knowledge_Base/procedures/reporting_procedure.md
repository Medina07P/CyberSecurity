# PROCEDIMIENTO DE REPORTE

## 1. Estructura del Informe

### 1.1 Portada
- Título
- Cliente
- Fecha
- Auditor

### 1.2 Resumen Ejecutivo
- Hallazgos principales
- Recomendaciones clave

### 1.3 Hallazgos Detallados
- ID
- Descripción
- Impacto
- Recomendación

### 1.4 Apéndice
- Metodología
- Herramientas
- Evidencias

## 2. Niveles de Severidad

| Nivel    | Descripción           | Plazo de Corrección |
|----------|-----------------------|---------------------|
| Crítico  | Riesgo inmediato      | 24 horas            |
| Alto     | Riesgo significativo  | 1 semana            |
| Medio    | Riesgo moderado       | 1 mes               |
| Bajo     | Riesgo menor          | 3 meses             |

## 3. Generación de Informes

```bash
# Generar informe completo
./report_generator.sh --full

# Generar todo (incluyendo HTML y PDF)
./report_generator.sh --all
```

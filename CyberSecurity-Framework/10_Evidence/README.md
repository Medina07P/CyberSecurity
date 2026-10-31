# 📂 10_Evidence - Evidencias Recolectadas

Este directorio contiene todas las evidencias recolectadas durante la auditoría.

## 📁 Estructura

| Directorio | Descripción |
|-----------|-------------|
| `screenshots/` | Capturas de pantalla |
| `pcaps/` | Capturas de tráfico de red |
| `credentials/` | Credenciales encontradas |
| `findings/` | Hallazgos y vulnerabilidades |
| `proofs/` | Pruebas de acceso y datos |
| `logs/` | Logs de la auditoría |

## 🚀 Uso Rápido

```bash
# Gestionar evidencias
./evidence_manager.sh --add screenshot web_login.png

# Verificar integridad
./evidence_manager.sh --verify

# Empaquetar evidencias
./evidence_manager.sh --package audit_2026
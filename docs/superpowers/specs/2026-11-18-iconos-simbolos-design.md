# Íconos Unicode simples en menú y documentación — diseño breve

Fecha: 2026-11-18. Estado: aprobado por el usuario en conversación.

## Intención

Los emojis a color se ven mal en la terminal y en parte de la documentación
(la máquina solo tiene Noto Color Emoji, sin Nerd Font). Se sustituyen por
símbolos Unicode monocromos, más sobrios y legibles en cualquier fuente.

## Objetivos

- Menú (`cyber_framework.sh`, `00_Config/lib/*.bash`) sin emojis a color.
- Documentación `.md` sin emojis: encabezados sin emoji; `✅/❌` pasan a
  `✔/✖` o a palabras (OK, Error, Aviso).
- Después, por separado, los ~89 scripts `.sh`/`.py` con mensajes con emoji.
- Suites de `tests/` actualizadas a los nuevos símbolos.

## No-objetivos / anti-objetivos

- No instalar Nerd Font, no cambiar colores ni estructura del menú.
- No cambiar lógica: solo texto visible. Una prueba que pase solo porque se
  relajó la aserción más allá del símbolo sería un fallo.
- No ejecutar `tests/run_tests.sh` sobre este checkout (borra evidencias).

## Enfoques considerados

1. **Mapa fijo de sustitución aplicado por fases (elegido).** Tabla única
   emoji → símbolo, aplicada a menú, docs, scripts y tests en commits separados.
   Simple, revisable, consistente.
2. Nerd Font: más vistoso, pero exige instalar y configurar fuente; descartado
   por el usuario.
3. ASCII puro (`[OK]`): máxima compatibilidad, menos legible; descartado.

## Mapa de sustitución

| Emoji | Símbolo |
|---|---|
| ✅ ✔️ | `✔` |
| ❌ ✗ ✖️ | `✖` |
| ⚠️ | `⚠` (sin `U+FE0F`) |
| ℹ️ 💡 | `ℹ` |
| ▶️ 🚀 ➜ | `▶` / `›` |
| 🎯 | `◎` |
| 📁 | `▪` |
| 🛠️ | `⚙` |
| 🛡️ 🔬 🤖 y de título | se quitan o `◆` |

Todo `U+FE0F` (selector emoji) se elimina.

## Ejecución

Rama aparte desde `develop` en worktree, commits separados (menú, docs,
scripts, tests), sin push. Verificación solo con suites seguras
(`run_smoke`, `run_config_menu`, `run_scanners_menu`, `run_reports`, etc.)
y `bash -n` capturando stderr.

## A criterio del implementador

Símbolo exacto de los emojis de título poco frecuentes; reformulación de
documentos donde el emoji era el único marcador de lista.

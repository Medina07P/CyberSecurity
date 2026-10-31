# Credenciales

Aquí se almacenan las credenciales obtenidas durante una auditoría
(usuarios, hashes, claves SSH, tokens de sesión).

## Reglas

- **Nunca** subir el contenido al repositorio: `00_Config/.gitignore` excluye
  todo lo que hay en este directorio salvo este README y `.gitkeep`.
- Cifrar lo que se guarde (`gpg`, `age`) si va a perdurar más que el proyecto.
- Un fichero por origen, con el formato `credenciales_<target>.txt`, para que el
  patrón de exclusión lo cubra.

## Estructura sugerida

```
credentials/
├── credenciales_<target>.txt
└── hashes_<target>.txt
```

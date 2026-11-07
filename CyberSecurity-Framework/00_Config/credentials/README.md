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

## `api-keys.yaml`: claves de API de las herramientas

`api-keys.yaml` no es una credencial obtenida en una auditoría: es el **registro propio**
del operador. Lo gestiona el gestor (opción `K`) o la CLI
`00_Config/scripts/api_keys.py`, y de él se escriben los ficheros de theHarvester, shodan,
h8mail, amass, recon-ng y spiderfoot.

- Formato: YAML con una sección por herramienta (`theharvester`, `shodan`, `h8mail`,
  `amass`, `recon-ng`, `spiderfoot`); los campos se anidan como en el ejemplo de cada una.
- Permisos: `600` el fichero y `700` este directorio. El helper los crea así; si copias el
  registro de otro sitio, repón los permisos con `chmod 600`.
- Está en `.gitignore`: no se sube nunca.
- Ninguna orden lo imprime con valores: `estado` solo dice presencia y longitud.
- **Borrar `api-keys.yaml` no borra las claves de las herramientas**: sus ficheros
  (`~/.theHarvester/api-keys.yaml`, `~/.shodan/api_key`, `~/.h8mail_config.ini`,
  `~/.config/amass/datasources.yaml`, `~/.recon-ng/keys.db`,
  `~/.spiderfoot/spiderfoot.db`) siguen con lo que tuvieran. `importar` las recupera.
  Para revocar una clave de verdad, bórrala con `-` desde el gestor o edita el fichero de
  la herramienta.

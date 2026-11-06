"""Parsers de las fuentes de hallazgos del motor de informes.

Cada módulo de este paquete traduce el formato de una herramienta a
``ParseResult`` y se registra en ``lib.sources`` al importarse. La carga la
provoca ``lib.sources._load_parsers``, con tolerancia a ``ImportError``: un
parser que aún no existe no impide evaluar los demás.
"""

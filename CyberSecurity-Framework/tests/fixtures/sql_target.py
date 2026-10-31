#!/usr/bin/env python3
"""Servidor de pruebas para sqlmap_request.sh.

Uso: python3 sql_target.py <puerto>

Escucha en 127.0.0.1 y expone una SQLi booleana de verdad sobre sqlite: el
parámetro `id` se concatena en la consulta sin escapar, así que un AND que sea
falso devuelve otra página. Es el blanco con el que se midió el coste de una
tanda de sqlmap (unas 51 peticiones con --technique=B).
"""

import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

CON = sqlite3.connect(":memory:", check_same_thread=False)
CON.execute("CREATE TABLE clientes (id INTEGER, nombre TEXT)")
CON.executemany("INSERT INTO clientes VALUES (?, ?)", [(1, "ana"), (2, "luis")])
CON.commit()


class Manejador(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _responder(self, codigo, cuerpo):
        datos = cuerpo.encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(datos)))
        self.end_headers()
        self.wfile.write(datos)

    def do_GET(self):
        consulta = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        valor = (consulta.get("id") or ["1"])[0]
        try:
            filas = CON.execute(
                "SELECT id, nombre FROM clientes WHERE id = " + valor
            ).fetchall()
        except Exception:
            self._responder(500, "error de SQL")
            return
        if filas:
            # La rama verdadera se parece a la respuesta original; la falsa no.
            cuerpo = " ".join("%s:%s" % fila for fila in filas)
            self._responder(200, "<html><body>%s</body></html>" % (cuerpo * 3))
        else:
            self._responder(200, "<html><body>sin resultados</body></html>")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    puerto = int(sys.argv[1]) if len(sys.argv) > 1 else 8001
    ThreadingHTTPServer(("127.0.0.1", puerto), Manejador).serve_forever()

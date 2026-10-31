#!/usr/bin/env python3
"""Servidor de pruebas para http_inject.sh.

Uso: python3 http_target.py <puerto>

Escucha en 127.0.0.1 y ofrece los casos que las suites necesitan:
reflejo sin escapar, reflejo escapado, endpoint que ignora el parámetro
(catch-all), par booleano de SQLi, error de BD, retardo, SSTI, respuesta
inestable y un login JSON que exige Cookie: sid=ok.
"""

import html
import json
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


_CONTADOR = 0
_CADUCA = 0
_MUERE = 0


class Manejador(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _responder(self, codigo, cuerpo, tipo="text/html; charset=utf-8"):
        datos = cuerpo.encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(datos)))
        self.end_headers()
        self.wfile.write(datos)

    def _valor(self):
        # El primer valor de la query, sea cual sea el nombre del parámetro.
        consulta = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        for valores in consulta.values():
            if valores:
                return valores[0]
        return ""

    def do_GET(self):
        ruta = urlparse(self.path).path
        valor = self._valor()

        if ruta in ("/echo", "/xss"):
            self._responder(200, "<html><body>reflejo: %s</body></html>" % valor)
        elif ruta == "/esc":
            self._responder(200, "<html><body>reflejo: %s</body></html>" % html.escape(valor))
        elif ruta == "/safe":
            self._responder(200, "<html><body>pagina fija</body></html>")
        elif ruta == "/sqli":
            if "AND '1'='2" in valor:
                self._responder(200, "<html><body>no hay resultados</body></html>")
            else:
                self._responder(200, "<html><body>lista con 3 filas</body></html>")
        elif ruta == "/err":
            if "'" in valor:
                self._responder(500, "You have an error in your SQL syntax near '%s'" % valor)
            else:
                self._responder(200, "<html><body>ok</body></html>")
        elif ruta == "/time":
            # Solo los payloads de tiempo de la SQLi: el resto de clases tiene
            # su propio endpoint y así cada caso mide lo suyo.
            if "pg_sleep" in valor.lower() or "sleep(" in valor.lower():
                time.sleep(1)
            self._responder(200, "<html><body>listo</body></html>")
        elif ruta == "/cmd":
            if "sleep" in valor.lower():
                time.sleep(1)
            self._responder(200, "<html><body>comando</body></html>")
        elif ruta == "/ssti":
            if "{{7*7}}" in valor:
                self._responder(200, "<html><body>49</body></html>")
            else:
                self._responder(200, "<html><body>%s</body></html>" % html.escape(valor))
        elif ruta == "/mostrar49":
            self._responder(200, "<html><body>Mostrando 49 resultados</body></html>")
        elif ruta == "/caduca":
            global _CADUCA
            _CADUCA += 1
            if _CADUCA > 6:
                self._responder(401, "<html><body>sesion caducada</body></html>")
            else:
                self._responder(200, "<html><body>panel privado</body></html>")
        elif ruta == "/muere":
            global _MUERE
            _MUERE += 1
            if _MUERE > 6:
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            self._responder(200, "<html><body>vivo</body></html>")
        elif ruta == "/unstable":
            global _CONTADOR
            _CONTADOR += 1
            relleno = ("nuevo", "viejo", "medio", "alto", "bajo", "raro",
                       "verde", "azul", "rojo", "gris")[_CONTADOR % 10]
            self._responder(200, "<html><body>estado: %s</body></html>" % relleno)
        else:
            self._responder(404, "no encontrado")

    def do_POST(self):
        ruta = urlparse(self.path).path
        longitud = int(self.headers.get("Content-Length") or 0)
        cuerpo = self.rfile.read(longitud).decode("utf-8", "replace")

        if ruta == "/pedido":
            self._responder(200, "<html><body>pedido registrado</body></html>")
        elif ruta == "/login":
            if "sid=ok" not in (self.headers.get("Cookie") or ""):
                self._responder(401, "<html><body>no autorizado</body></html>")
                return
            try:
                datos = json.loads(cuerpo) if cuerpo else {}
            except ValueError:
                datos = {}
            usuario = datos.get("user", "")
            self._responder(200, "<html><body>bienvenido %s</body></html>" % html.escape(str(usuario)))
        else:
            self._responder(404, "no encontrado")


if __name__ == "__main__":
    puerto = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    servidor = ThreadingHTTPServer(("127.0.0.1", puerto), Manejador)
    servidor.serve_forever()

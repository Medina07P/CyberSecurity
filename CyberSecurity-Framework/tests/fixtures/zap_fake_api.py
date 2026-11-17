#!/usr/bin/env python3
"""Servidor de pruebas que imita la API JSON de OWASP ZAP.

Uso: python3 zap_fake_api.py <puerto> [fichero_ready]

Nunca es un daemon ZAP real: solo responde los endpoints JSON que
zap_driver.py necesita, con estado configurable por variables de entorno
leídas una vez al arrancar:

  ZAP_FAKE_SPIDER_STATUSES   lista separada por comas (por defecto "100")
  ZAP_FAKE_PSCAN_COUNTS      lista separada por comas (por defecto "0")
  ZAP_FAKE_ALERTS_FILE       ruta a un JSON con la lista de alertas (si falta, [])
  ZAP_FAKE_IGNORE_SHUTDOWN   "1" para que /core/action/shutdown/ no apague el server

python3-zapv2 habla con el daemon a través de un proxy HTTP: la línea de
petición puede traer la URL absoluta («http://zap/JSON/...») en vez de una
ruta pelada, así que aquí también se analiza con urlparse().path.
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


def _lista_enteros(valor, defecto):
    bruto = valor if valor is not None else defecto
    return [p.strip() for p in bruto.split(',') if p.strip() != '']


_SPIDER_STATUSES = _lista_enteros(os.environ.get('ZAP_FAKE_SPIDER_STATUSES'), '100')
_PSCAN_COUNTS = _lista_enteros(os.environ.get('ZAP_FAKE_PSCAN_COUNTS'), '0')
_IGNORE_SHUTDOWN = os.environ.get('ZAP_FAKE_IGNORE_SHUTDOWN') == '1'
_ALERTS_FILE = os.environ.get('ZAP_FAKE_ALERTS_FILE')

_spider_idx = 0
_pscan_idx = 0


def _siguiente(lista, indice_actual):
    """Consume el próximo valor de la lista; se queda en el último al agotarla."""
    idx = min(indice_actual, len(lista) - 1)
    valor = lista[idx]
    return valor, idx + 1


class Manejador(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _json(self, cuerpo_dict):
        datos = json.dumps(cuerpo_dict).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(datos)))
        self.end_headers()
        self.wfile.write(datos)

    def do_GET(self):
        global _spider_idx, _pscan_idx
        ruta = urlparse(self.path).path
        if ruta == '/JSON/core/view/version/':
            self._json({'version': 'fake'})
        elif ruta == '/JSON/spider/action/scan/':
            self._json({'scan': '0'})
        elif ruta == '/JSON/spider/view/status/':
            valor, _spider_idx = _siguiente(_SPIDER_STATUSES, _spider_idx)
            self._json({'status': valor})
        elif ruta == '/JSON/spider/action/stop/':
            self._json({'Result': 'OK'})
        elif ruta == '/JSON/pscan/view/recordsToScan/':
            valor, _pscan_idx = _siguiente(_PSCAN_COUNTS, _pscan_idx)
            self._json({'recordsToScan': valor})
        elif ruta == '/JSON/core/view/alerts/':
            alertas = []
            if _ALERTS_FILE:
                with open(_ALERTS_FILE, encoding='utf-8') as f:
                    alertas = json.load(f)
            self._json({'alerts': alertas})
        elif ruta == '/JSON/core/action/shutdown/':
            self._json({'Result': 'OK'})
            if not _IGNORE_SHUTDOWN:
                # Apagar desde el propio hilo del manejador bloquearía
                # serve_forever(); se hace desde un hilo aparte.
                threading.Thread(target=self.server.shutdown, daemon=True).start()
        else:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()


if __name__ == '__main__':
    puerto = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    servidor = ThreadingHTTPServer(('127.0.0.1', puerto), Manejador)
    if len(sys.argv) > 2:
        with open(sys.argv[2], 'x', encoding='ascii') as ready:
            ready.write(f'{os.getpid()} {servidor.server_port}\n')
    servidor.serve_forever()

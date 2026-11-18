#!/usr/bin/env python3
"""Servidor de pruebas que imita la API de Ollama (solo loopback).

Uso: python3 ollama_fake.py <puerto|0> <fichero_ready>

El fichero ready recibe "pid puerto" cuando el servidor ya escucha.
Nunca es un Ollama real. Variables de entorno:

  FAKE_OLLAMA_MODE  ok | no_model | truncated | slow | redirect (307 a FAKE_OLLAMA_REDIRECT_TO)
                    | bad_message (un trozo con "message" no-dict)  (por defecto ok)
  FAKE_OLLAMA_LOG   ruta donde se guarda el último cuerpo de /api/chat
  FAKE_OLLAMA_MODEL nombre del modelo que anuncia /api/tags (por defecto "fake:1b")
"""

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE = os.environ.get('FAKE_OLLAMA_MODE', 'ok')
LOG = os.environ.get('FAKE_OLLAMA_LOG')
MODEL = os.environ.get('FAKE_OLLAMA_MODEL', 'fake:1b')
# FAKE_OLLAMA_MODELS (coma-separado) anuncia varios modelos en /api/tags, para
# probar el listado del selector sin tocar el modo de un solo modelo que ya
# usan las demas pruebas.
_MODELS_ENV = os.environ.get('FAKE_OLLAMA_MODELS')
MODELS = [m for m in _MODELS_ENV.split(',') if m] if _MODELS_ENV else [MODEL]
CHUNKS = ['Hola', ', ', 'mundo']


class Manejador(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def _json(self, codigo, cuerpo):
        datos = json.dumps(cuerpo).encode('utf-8')
        self.send_response(codigo)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(datos)))
        self.end_headers()
        self.wfile.write(datos)

    def do_GET(self):
        if self.path.split('?')[0] != '/api/tags':
            return self._json(404, {'error': 'no encontrado'})
        modelos = [] if MODE == 'no_model' else [{'name': m} for m in MODELS]
        self._json(200, {'models': modelos})

    def do_POST(self):
        largo = int(self.headers.get('Content-Length') or 0)
        crudo = self.rfile.read(largo)
        if self.path.split('?')[0] != '/api/chat':
            return self._json(404, {'error': 'no encontrado'})
        if LOG:
            with open(LOG, 'wb') as f:
                f.write(crudo)
        if MODE == 'redirect':
            self.send_response(307)
            self.send_header('Location', os.environ.get('FAKE_OLLAMA_REDIRECT_TO', ''))
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if MODE == 'no_model':
            return self._json(404, {'error': 'model not found'})
        try:
            cuerpo = json.loads(crudo or b'{}')
        except ValueError:
            return self._json(400, {'error': 'json invalido'})
        if cuerpo.get('stream') is False:
            return self._json(200, {'message': {'role': 'assistant', 'content': ''},
                                    'done': True})
        self.send_response(200)
        self.send_header('Content-Type', 'application/x-ndjson')
        self.end_headers()
        if MODE == 'bad_message':
            self.wfile.write((json.dumps({'message': ['no es un dict'],
                                          'done': False}) + '\n').encode('utf-8'))
            self.wfile.write((json.dumps({'message': {'role': 'assistant', 'content': ''},
                                          'done': True}) + '\n').encode('utf-8'))
            return
        for trozo in CHUNKS:
            linea = json.dumps({'message': {'role': 'assistant', 'content': trozo},
                                'done': False}) + '\n'
            self.wfile.write(linea.encode('utf-8'))
            self.wfile.flush()
            if MODE == 'slow':
                time.sleep(0.5)
        if MODE == 'truncated':
            self.wfile.write(b'{"message": {"role": "assistant", "conte')
            self.wfile.flush()
            return
        self.wfile.write((json.dumps({'message': {'role': 'assistant', 'content': ''},
                                      'done': True}) + '\n').encode('utf-8'))


def main():
    puerto = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    ready = sys.argv[2] if len(sys.argv) > 2 else None
    srv = ThreadingHTTPServer(('127.0.0.1', puerto), Manejador)
    if ready:
        with open(ready, 'w') as f:
            f.write("%d %d" % (os.getpid(), srv.server_address[1]))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()

"""Transporte sintético para subprocess; se instala SOLO desde sitecustomize de tests."""
import io
import json
import os
import socket
import urllib.request
from pathlib import Path


class Response(io.BytesIO):
    def __init__(self, body, url, status=200):
        super().__init__(body)
        self.status, self.url, self.headers = status, url, {}

    def geturl(self):
        return self.url


def install():
    def forbidden(*args, **kwargs):
        raise AssertionError('Prueba OSINT: red externa prohibida')
    socket.create_connection = forbidden
    socket.socket.connect = forbidden

    def fake_open(self, req, *args, **kwargs):
        url = req.full_url
        log = Path(os.environ['OSINT_FIXTURE_LOG'])
        with log.open('a') as stream:
            stream.write(url + '\n')
        if 'api.github.com/search/users?' in url:
            data = {'total_count': 1, 'incomplete_results': False,
                    'items': [{'login': 'acme', 'html_url': 'https://github.com/acme', 'type': 'Organization'}]}
        elif url.startswith('https://crt.sh/'):
            data = [{'name_value': 'www.example.test'}]
        elif url.startswith('https://example.test/'):
            if os.environ.get('OSINT_FIXTURE_MODE') == 'blocked':
                return Response(b'access denied', url, 403)
            return Response(b'<html><a href="https://github.com/acme">GitHub</a><a href="mailto:info@example.test">Email</a></html>', url)
        else:
            raise AssertionError('Solicitud no prevista: ' + url)
        return Response(json.dumps(data).encode(), url)
    urllib.request.OpenerDirector.open = fake_open

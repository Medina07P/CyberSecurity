"""Cliente mínimo de Ollama: solo loopback salvo permiso explícito."""
import ipaddress
import json
import socket
from urllib.parse import urlparse

import requests


class OllamaError(Exception):
    """Error del asistente con un mensaje en español, sin tracebacks."""

    def __init__(self, user_message):
        super().__init__(user_message)
        self.user_message = user_message


def _is_loopback(host):
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    try:
        return ipaddress.ip_address(socket.gethostbyname(host)).is_loopback
    except (OSError, ValueError):
        return False


class OllamaClient:
    def __init__(self, endpoint, model, allow_remote=False, timeout=120):
        host = urlparse(endpoint).hostname
        if allow_remote is not True and not _is_loopback(host):
            raise OllamaError(
                "El endpoint de Ollama (%s) no es local. Por seguridad nada sale "
                "de esta máquina salvo que se permita explícitamente." % endpoint)
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout = timeout
        # Sin proxies del entorno: nada de lo local debe salir por HTTP(S)_PROXY.
        self._http = requests.Session()
        self._http.trust_env = False

    def _no_server(self):
        return OllamaError(
            "No se pudo conectar con Ollama en %s. Comprueba que está "
            "arrancado (ollama serve)." % self.endpoint)

    def _no_model(self):
        return OllamaError(
            "El modelo %s no está instalado en Ollama. Descárgalo con: "
            "ollama pull %s" % (self.model, self.model))

    def is_up(self):
        try:
            return self._http.get(self.endpoint + "/api/tags", timeout=min(self.timeout, 5), allow_redirects=False).status_code == 200
        except requests.RequestException:
            return False

    def has_model(self):
        try:
            r = self._http.get(self.endpoint + "/api/tags", timeout=min(self.timeout, 5), allow_redirects=False)
            names = [m.get("name") for m in r.json().get("models", [])]
        except (requests.RequestException, ValueError, AttributeError):
            return False
        return self.model in names or (self.model + ":latest") in names

    def chat(self, messages, *, stream_to=None, keep_alive="5m"):
        payload = {"model": self.model, "messages": messages, "stream": True,
                   "keep_alive": keep_alive}
        parts = []
        try:
            with self._http.post(self.endpoint + "/api/chat", json=payload,
                               stream=True, timeout=self.timeout, allow_redirects=False) as r:
                if 300 <= r.status_code < 400:
                    raise OllamaError(
                        "Ollama intentó redirigir la petición a otra dirección; "
                        "por seguridad no se sigue.")
                if r.status_code == 404:
                    raise self._no_model()
                if r.status_code != 200:
                    raise OllamaError("Ollama respondió con un error (HTTP %d)." % r.status_code)
                done = False
                for line in r.iter_lines():
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        raise OllamaError(
                            "La respuesta de Ollama llegó cortada o ilegible; "
                            "inténtalo de nuevo.")
                    if not isinstance(obj, dict):
                        raise OllamaError("Respuesta inesperada de Ollama.")
                    if obj.get("error"):
                        raise OllamaError("Ollama devolvió un error: %s" % obj["error"])
                    trozo = (obj.get("message") or {}).get("content", "")
                    if trozo:
                        parts.append(trozo)
                        if stream_to:
                            stream_to(trozo)
                    if obj.get("done"):
                        done = True
                if not done:
                    raise OllamaError(
                        "La respuesta de Ollama se interrumpió antes de terminar.")
        except requests.ConnectionError:
            raise self._no_server()
        except requests.Timeout:
            raise OllamaError("Ollama tardó demasiado en responder (más de %ds)." % self.timeout)
        except requests.RequestException:
            raise OllamaError("Fallo de comunicación con Ollama.")
        return "".join(parts)

    def unload(self):
        try:
            self._http.post(self.endpoint + "/api/chat",
                          json={"model": self.model, "messages": [], "stream": False,
                                "keep_alive": 0}, timeout=min(self.timeout, 10), allow_redirects=False)
        except requests.RequestException:
            pass

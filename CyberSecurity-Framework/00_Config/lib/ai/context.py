"""Gestor de contexto del asistente: turnos literales recientes + resumen.

Clase pura en memoria: no toca el sistema de ficheros ni registra contenido.
"""
from typing import Callable, Optional

ROLES = ("user", "assistant", "system")
SUMMARY_CAP = 2000
EXTRACT_CHARS = 200
WARN_PERCENT = 80
SUMMARY_LABEL = "Resumen de la conversación anterior: "


def estimate_tokens(text: str) -> int:
    """Estimación barata: ~4 caracteres por token."""
    return len(text) // 4


def _extractive(msgs: list) -> str:
    return "\n".join(f"{m['role']}: {m['content'][:EXTRACT_CHARS]}" for m in msgs)


def _cap(text: str) -> str:
    """Recorta lo más antiguo (el principio) hasta SUMMARY_CAP."""
    return text if len(text) <= SUMMARY_CAP else text[-SUMMARY_CAP:]


class Conversation:
    def __init__(self, max_tokens: int, literal_turns: int = 6,
                 summarizer: Optional[Callable[[list], str]] = None):
        self.max_tokens = max_tokens
        self.literal_turns = max(1, literal_turns)
        self.summarizer = summarizer
        self.summary = ""
        self._turns: list = []

    def add(self, role: str, content: str) -> None:
        if role not in ROLES:
            raise ValueError(f"rol desconocido: {role!r}")
        if not isinstance(content, str) or not content.strip():
            return  # los mensajes vacíos no aportan contexto
        self._turns.append({"role": role, "content": content})
        if len(self._turns) > self.literal_turns:
            dropped = self._turns[:-self.literal_turns]
            self._turns = self._turns[-self.literal_turns:]
            self._fold(dropped)

    def _fold(self, dropped: list) -> None:
        text = None
        if self.summarizer is not None:
            try:
                prior = ([{"role": "system", "content": SUMMARY_LABEL + self.summary}]
                         if self.summary else [])
                out = self.summarizer(prior + dropped)
                if isinstance(out, str) and out.strip():
                    text = _cap(out.strip())
                    self.summary = text
                    return
            except Exception:
                text = None
        extra = _extractive(dropped)
        self.summary = _cap(f"{self.summary}\n{extra}" if self.summary else extra)

    def messages(self) -> list:
        out = []
        if self.summary:
            out.append({"role": "system", "content": SUMMARY_LABEL + self.summary})
        out.extend(dict(m) for m in self._turns)
        return out

    def usage_percent(self) -> int:
        tokens = estimate_tokens(self.summary) + sum(
            estimate_tokens(m["content"]) for m in self._turns)
        if self.max_tokens <= 0:
            return 100 if tokens > 0 else 0
        return max(0, min(100, tokens * 100 // self.max_tokens))

    def needs_warning(self) -> bool:
        return self.usage_percent() >= WARN_PERCENT

    def reset(self, save_summary: bool = False) -> Optional[str]:
        result = None
        if save_summary:
            # El resumen acumulado y los turnos aún sin plegar son conjuntos
            # disjuntos de historia; perder uno de los dos pierde contexto que
            # el usuario pidió explícitamente conservar.
            parts = []
            if self.summary:
                parts.append(self.summary)
            if self._turns:
                parts.append(_extractive(self._turns))
            if parts:
                result = "\n".join(parts)
        self.summary = ""
        self._turns = []
        return result

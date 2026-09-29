"""Mentions légales et notice de confidentialité fournies par l'exploitant de l'instance.

Les textes vivent dans des fichiers Markdown de l'exploitant (LEGAL_FILE, PRIVACY_FILE), lus à chaque
affichage. Seul un sous-ensemble sûr est rendu : titres, paragraphes, listes, gras et liens https ou
mailto, ou vers une page de l'instance. Tout le reste est échappé, y compris le HTML écrit dans le fichier.
"""

import re
from pathlib import Path

from markupsafe import Markup, escape

LINK = re.compile(r"\[([^\]\n]{1,200})\]\(((?:https://|mailto:|/(?![/\\]))[^\s()<>\"'\\]{0,500})\)")
BOLD = re.compile(r"\*\*([^*\n]{1,300})\*\*")


def _inline(text: str) -> str:
    escaped = str(escape(text))
    escaped = BOLD.sub(r"<strong>\1</strong>", escaped)
    # Liens reconnus après échappement : l'URL ne peut contenir ni guillemet ni chevron, et seuls https,
    # mailto et un chemin de l'instance passent (jamais javascript:, data: ni //autre-site).
    return LINK.sub(lambda m: f'<a href="{m.group(2)}" rel="noopener">{m.group(1)}</a>', escaped)


def render_markdown(text: str) -> Markup:
    blocks: list[str] = []
    paragraph: list[str] = []
    items: list[str] = []

    def close() -> None:
        if paragraph:
            blocks.append("<p>" + " ".join(_inline(line) for line in paragraph) + "</p>")
            paragraph.clear()
        if items:
            blocks.append("<ul>" + "".join(f"<li>{_inline(item)}</li>" for item in items) + "</ul>")
            items.clear()

    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        heading = re.match(r"^(#{1,3})\s+(.+)$", line)
        if not line:
            close()
        elif heading:
            close()
            # Le titre de la page est le h1 du gabarit : les titres du fichier commencent au h2.
            level = len(heading.group(1)) + 1
            blocks.append(f"<h{level}>{_inline(heading.group(2))}</h{level}>")
        elif line.startswith(("- ", "* ")):
            if paragraph:
                close()
            items.append(line[2:].strip())
        else:
            if items:
                close()
            paragraph.append(line)
    close()
    return Markup("\n".join(blocks))


def load(path: str | None) -> Markup | None:
    """Texte rendu, ou None si l'exploitant n'a rien publié (fichier absent, illisible ou vide)."""
    if not path:
        return None
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    return render_markdown(text[:200_000]) if text.strip() else None

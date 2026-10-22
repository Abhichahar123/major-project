"""List the Gemini models available to the configured API key.

    python -m app.llm.gemini_models

Google renames and retires Gemini models, and free-tier availability differs between
models, so this project ships no default model code. Run this command to see which codes
the key can use for generation (``generateContent``) and embeddings (``embedContent``),
then set ``GEMINI_MODEL`` / ``GEMINI_EMBEDDING_MODEL``. Whether a model is free of charge
is stated on Google's pricing page and in AI Studio, not in this listing.
"""

from __future__ import annotations

import sys

import httpx
from google.genai import errors as genai_errors

from app.core.config import load_settings
from app.core.exceptions import ConfigurationError
from app.core.gemini import classify_error, make_client

_ACTIONS = {"generateContent": "generation", "embedContent": "embeddings"}


def main() -> int:
    try:
        settings = load_settings()
    except ConfigurationError as exc:
        print(exc, file=sys.stderr)
        return 2
    if settings.gemini_api_key is None:
        print("GEMINI_API_KEY is not set (backend .env only).", file=sys.stderr)
        return 2
    client = make_client(settings.gemini_api_key.get_secret_value(), timeout_seconds=30)
    try:
        models = list(client.models.list())
    except (genai_errors.APIError, httpx.HTTPError) as exc:
        failure = classify_error(exc, "-")
        print(
            f"Could not list models: {failure.message if failure else 'unexpected error'}",
            file=sys.stderr,
        )
        return 1
    for model in sorted(models, key=lambda m: m.name or ""):
        uses = [
            label for action, label in _ACTIONS.items() if action in (model.supported_actions or [])
        ]
        if uses:
            name = (model.name or "").removeprefix("models/")
            print(f"{name:45} {', '.join(uses)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

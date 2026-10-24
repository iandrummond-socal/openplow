"""Model pricing and cost estimation.

Prices are USD per million tokens, first-party Anthropic API rates (cached
2026-10-06; see the Claude API reference). They move, so treat the output as an
*estimate* and update the table when rates change. Unknown models price at zero
with a note rather than guessing.
"""

from __future__ import annotations

from dataclasses import dataclass

# model_id -> (input $/MTok, output $/MTok, cache-read $/MTok)
# cache-read defaults to 0.1 x input when not given explicitly.
PRICES: dict[str, tuple[float, float, float]] = {
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-opus-5": (5.00, 25.00, 0.50),
    "claude-opus-4-8": (5.00, 25.00, 0.50),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20),
    "claude-sonnet-5": (2.00, 10.00, 0.20),
    "claude-haiku-5-5": (0.10, 0.50, 0.02),
    "claude-haiku-4-5": (1.00, 5.00, 0.10),
    "claude-fable-5-1": (10.00, 50.00, 1.00),
    "claude-fable-5": (10.00, 50.00, 1.00),
}

_CACHE_CREATION_MULT = 1.25  # cache writes cost ~1.25x base input


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
            self.cache_read_tokens + other.cache_read_tokens,
            self.cache_creation_tokens + other.cache_creation_tokens,
        )


def model_from_adapter_name(name: str) -> str | None:
    """Pull a model id out of an adapter name like 'anthropic:claude-opus-5-5'."""
    if ":" in name:
        return name.split(":", 1)[1]
    return name if name in PRICES else None


def estimate_cost(model: str, usage: Usage) -> float | None:
    """Estimated USD for one model's usage, or None if the model is unpriced."""
    rate = PRICES.get(model)
    if rate is None:
        return None
    inp, out, cache_read = rate
    dollars = (
        usage.input_tokens * inp
        + usage.output_tokens * out
        + usage.cache_read_tokens * cache_read
        + usage.cache_creation_tokens * inp * _CACHE_CREATION_MULT
    ) / 1_000_000
    return round(dollars, 4)

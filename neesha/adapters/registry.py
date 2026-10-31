"""Adapter registry.

Selection is by capability, not by name: a Priority Intelligence Requirement
names the attributes that would answer it, and the registry returns the
adapters able to produce them, cheapest tier first. That is what makes
planning a deterministic table lookup rather than a model call — and it means
adding an adapter widens what the planner can answer without touching the
planner.
"""
from __future__ import annotations

from typing import Any, Iterable, Optional, Type

from neesha.adapters.base import BaseAdapter
from neesha.adapters.crtsh import CrtShAdapter
from neesha.adapters.hunter import HunterAdapter

_REGISTERED: tuple[Type[BaseAdapter], ...] = (
    CrtShAdapter,
    HunterAdapter,
)

ADAPTERS: dict[str, Type[BaseAdapter]] = {cls.name: cls for cls in _REGISTERED}

# Free first, then metered, then the manual and contract-gated ones. The gate
# enforces authority; this only decides what the planner reaches for first.
TIER_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3}


def get(name: str) -> Optional[Type[BaseAdapter]]:
    return ADAPTERS.get(name)


def build(name: str, **kwargs) -> Any:
    cls = ADAPTERS.get(name)
    if cls is None:
        raise KeyError(f"unknown adapter {name!r}")
    return cls(**kwargs)


def for_attributes(
    attributes: Iterable[str], tiers: Optional[set[str]] = None
) -> list[Type[BaseAdapter]]:
    """Adapters that can produce any of these attributes, cheapest first."""
    wanted = frozenset(attributes)
    matches = [
        cls
        for cls in ADAPTERS.values()
        if cls.can_answer(wanted) and (tiers is None or cls.tier in tiers)
    ]
    return sorted(matches, key=lambda c: (TIER_ORDER.get(c.tier, 9), c.name))


def produced_attributes(tiers: Optional[set[str]] = None) -> frozenset[str]:
    """Everything the registry can currently produce.

    The planner subtracts a PIR's needs from this to report honestly on what
    it cannot answer, instead of silently under-delivering.
    """
    out: set[str] = set()
    for cls in ADAPTERS.values():
        if tiers is None or cls.tier in tiers:
            out |= set(cls.produces)
    return frozenset(out)

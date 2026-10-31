"""Collector registry.

The registry is the plugin surface: a collector is a class implementing the
Collector contract (name, source, description, tier, run).

Tiers come from the spec. Only Tier A — free and always-on — runs by default.
Metered (B), authority-gated (C) and contract-gated (D) collectors must be
named explicitly, and Tier D is not runnable at all until a contract and
credentials are supplied. Until the budget ledger lands, "named explicitly"
is the only thing standing between a default invocation and a metered API
call, which is why the default set is computed rather than hand-written.
AUDIT.md S1.
"""
from __future__ import annotations

from typing import Optional, Type

from neesha.collectors.base import Collector
from neesha.collectors.enrichment import ApolloAdapter, HunterAdapter, ZoomInfoAdapter
from neesha.collectors.osint import (
    CrtShCollector,
    HackerTargetCollector,
    OtxCollector,
    TheHarvesterCollector,
    UrlscanCollector,
    WaybackCollector,
)

_ALL: tuple[Type[Collector], ...] = (
    CrtShCollector,
    OtxCollector,
    WaybackCollector,
    UrlscanCollector,
    HackerTargetCollector,
    TheHarvesterCollector,
    HunterAdapter,
    ApolloAdapter,
    ZoomInfoAdapter,
)

# Every known collector, including ones that will not run without a contract.
ALL_COLLECTORS: dict[str, Type[Collector]] = {cls.name: cls for cls in _ALL}

# Tier D is built but disabled: present in ALL_COLLECTORS so it can be listed
# and described, absent from the runnable set.
RUNNABLE_COLLECTORS: dict[str, Type[Collector]] = {
    name: cls for name, cls in ALL_COLLECTORS.items() if cls.tier != "D"
}

# What a bare `neesha passive <domain>` is allowed to run: free sources only.
DEFAULT_COLLECTORS: dict[str, Type[Collector]] = {
    name: cls for name, cls in ALL_COLLECTORS.items() if cls.tier == "A"
}

METERED_TIERS = {"B", "C"}

# Retained for backwards compatibility with existing callers and tests.
PASSIVE_COLLECTORS = RUNNABLE_COLLECTORS


def get_collector(name: str) -> Optional[Type[Collector]]:
    return RUNNABLE_COLLECTORS.get(name)


def list_collectors() -> list[tuple[str, str, str]]:
    """Return (name, tier, description) for every known collector."""
    return [(cls.name, cls.tier, cls.description) for cls in ALL_COLLECTORS.values()]


def is_metered(name: str) -> bool:
    cls = ALL_COLLECTORS.get(name)
    return bool(cls and cls.tier in METERED_TIERS)

"""Collector registry.

The registry is the plugin surface: a collector is a class implementing the
Collector contract (name, source, description, run). Phase 13 formalizes
third-party plugin SDKs; this registry already exposes the same shape.
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

PASSIVE_COLLECTORS: dict[str, Type[Collector]] = {
    cls.name: cls
    for cls in (
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
}


def get_collector(name: str) -> Optional[Type[Collector]]:
    return PASSIVE_COLLECTORS.get(name)


def list_collectors() -> list[tuple[str, str]]:
    return [(cls.name, cls.description) for cls in PASSIVE_COLLECTORS.values()]

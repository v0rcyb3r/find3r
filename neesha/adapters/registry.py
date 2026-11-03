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
from neesha.adapters.company_web import CompanyWebAdapter
from neesha.adapters.dns_posture import DnsPostureAdapter
from neesha.adapters.otx import OtxAdapter
from neesha.adapters.wayback import WaybackAdapter
from neesha.adapters.urlscan import UrlscanAdapter
from neesha.adapters.subfinder import SubfinderAdapter
from neesha.adapters.intelx import IntelXAdapter
from neesha.adapters.dehashed import DeHashedAdapter
from neesha.adapters.github_email import GitHubEmailAdapter
from neesha.adapters.gravatar import GravatarAdapter
from neesha.adapters.emailrep import EmailRepAdapter
from neesha.adapters.holehe import HoleheAdapter
from neesha.adapters.socialscan import SocialscanAdapter
from neesha.adapters.sherlock import SherlockAdapter
from neesha.adapters.maigret import MaigretAdapter
from neesha.adapters.rdap import RdapAdapter
from neesha.adapters.internetdb import InternetDbAdapter
from neesha.adapters.hackertarget import HackerTargetAdapter
from neesha.adapters.amass import AmassAdapter
from neesha.adapters.email_osint import EmailOsintAdapter
from neesha.adapters.username_osint import UsernameOsintAdapter
from neesha.adapters.theharvester import TheHarvesterAdapter

_REGISTERED: tuple[Type[BaseAdapter], ...] = (
    CrtShAdapter,
    HunterAdapter,
    CompanyWebAdapter,
    DnsPostureAdapter,
    OtxAdapter,
    WaybackAdapter,
    UrlscanAdapter,
    SubfinderAdapter,
    AmassAdapter,
    TheHarvesterAdapter,
    RdapAdapter,
    InternetDbAdapter,
    HackerTargetAdapter,
    IntelXAdapter,
    DeHashedAdapter,
    GitHubEmailAdapter,
    GravatarAdapter,
    EmailRepAdapter,
    EmailOsintAdapter,
    UsernameOsintAdapter,
    HoleheAdapter,
    SocialscanAdapter,
    SherlockAdapter,
    MaigretAdapter,
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
    attributes: Iterable[str], tiers: Optional[set[str]] = None, sources: Optional[set[str]] = None
) -> list[Type[BaseAdapter]]:
    """Adapters that can produce any of these attributes, cheapest first."""
    wanted = frozenset(attributes)
    matches = [
        cls
        for cls in ADAPTERS.values()
        if cls.can_answer(wanted) and (tiers is None or cls.tier in tiers)
        and (cls.name in sources if sources is not None else cls.default_enabled)
    ]
    return sorted(matches, key=lambda c: (TIER_ORDER.get(c.tier, 9), c.name))


def produced_attributes(tiers: Optional[set[str]] = None, sources: Optional[set[str]] = None) -> frozenset[str]:
    """Everything the registry can currently produce.

    The planner subtracts a PIR's needs from this to report honestly on what
    it cannot answer, instead of silently under-delivering.
    """
    out: set[str] = set()
    for cls in ADAPTERS.values():
        if (tiers is None or cls.tier in tiers) and (cls.name in sources if sources is not None else cls.default_enabled):
            out |= set(cls.produces)
    return frozenset(out)


def catalog() -> list[dict]:
    """Configured capabilities, not a claim that external providers are healthy."""
    import os
    from neesha.adapters.tool_installer import INSTALLABLE_TOOLS, ensure_tool_paths_in_env

    ensure_tool_paths_in_env()
    rows = []
    for cls in ADAPTERS.values():
        ready, reason = True, 'Available; provider availability and rate limits can vary.'
        if cls.name == 'hunter' and not os.environ.get('HUNTER_API_KEY'):
            ready, reason = False, 'Needs Hunter credentials and a configured budget.'
        if hasattr(cls, 'availability'):
            availability = cls().availability()
            ready, reason = availability['available'], availability['reason']
        installable = cls.name in INSTALLABLE_TOOLS
        bin_path = cls.binary() if hasattr(cls, 'binary') and callable(getattr(cls, 'binary')) else None
        state = 'available' if ready else ('not installed' if installable else 'not configured')
        rows.append({'name': cls.name, 'description': cls.description,
                     'accepts': sorted(cls.accepts),
                     'tier': cls.tier, 'mode': cls.collection_mode, 'ready': ready,
                     'available': ready,
                     'installable': installable,
                     'binary_path': bin_path,
                     'state': state, 'reason': reason,
                     'integrated': bool(cls.produces)})
    return rows

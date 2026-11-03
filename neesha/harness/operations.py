"""Intelligence Operations & Tradecraft Engine.

Provides:
1. Operation Cases / Multi-Run Dossier Fusion & Cross-Target Correlation
2. Temporal Attack Surface Diffing (Run Delta Engine)
3. Analyst Pinboard & Timestamped Entity/Evidence Notes
4. Analysis of Competing Hypotheses (ACH) Admiralty-Weighted Matrix
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import threading
from typing import Any, Callable
from uuid import uuid4

from neesha.config import harden_path
from neesha.harness.graph import build_graph
from neesha.harness.mapping import build_geo_map
from neesha.harness.scoring import grade_brief_posture

_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}\Z")

ADMIRALTY_WEIGHTS: dict[str, int] = {
    "A1": 5,
    "A2": 4,
    "B1": 4,
    "B2": 3,
    "B3": 3,
    "C1": 3,
    "C2": 3,
    "C3": 2,
    "D4": 1,
    "E5": 1,
    "F6": 1,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def diff_briefs(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compute a structured Attack Surface & Evidence Delta between two runs."""
    base_facts = baseline.get("facts") or []
    curr_facts = current.get("facts") or []

    def fact_key(f: dict[str, Any]) -> tuple[str, str, str]:
        return (
            str(f.get("subject") or "").strip().lower(),
            str(f.get("attribute") or "").strip(),
            str(f.get("value") or "").strip(),
        )

    base_map = {fact_key(f): f for f in base_facts}
    curr_map = {fact_key(f): f for f in curr_facts}

    added_keys = [k for k in curr_map if k not in base_map]
    removed_keys = [k for k in base_map if k not in curr_map]
    unchanged_count = sum(1 for k in curr_map if k in base_map)

    added_facts = [curr_map[k] for k in added_keys[:150]]
    removed_facts = [base_map[k] for k in removed_keys[:150]]

    base_ips = {p["ip"]: p for p in ((baseline.get("geo_map") or {}).get("points") or []) if isinstance(p, dict) and p.get("ip")}
    curr_ips = {p["ip"]: p for p in ((current.get("geo_map") or {}).get("points") or []) if isinstance(p, dict) and p.get("ip")}
    added_geo = [curr_ips[ip] for ip in sorted(curr_ips) if ip not in base_ips]
    removed_geo = [base_ips[ip] for ip in sorted(base_ips) if ip not in curr_ips]

    # Port & CVE drift on surviving IPs
    host_changes: list[dict[str, Any]] = []
    for ip in sorted(set(base_ips) & set(curr_ips)):
        b_pt = base_ips[ip]
        c_pt = curr_ips[ip]
        new_ports = sorted(set(c_pt.get("ports") or []) - set(b_pt.get("ports") or []))
        closed_ports = sorted(set(b_pt.get("ports") or []) - set(c_pt.get("ports") or []))
        new_vulns = sorted(set(c_pt.get("vulns") or []) - set(b_pt.get("vulns") or []))
        fixed_vulns = sorted(set(b_pt.get("vulns") or []) - set(c_pt.get("vulns") or []))
        if new_ports or closed_ports or new_vulns or fixed_vulns:
            host_changes.append({
                "ip": ip,
                "new_ports": new_ports,
                "closed_ports": closed_ports,
                "new_vulns": new_vulns,
                "fixed_vulns": fixed_vulns,
            })

    base_exp = {str(e.get("id") or e.get("title") or ""): e for e in (baseline.get("exposures") or [])}
    curr_exp = {str(e.get("id") or e.get("title") or ""): e for e in (current.get("exposures") or [])}
    new_exposures = [curr_exp[k] for k in curr_exp if k not in base_exp]
    resolved_exposures = [base_exp[k] for k in base_exp if k not in curr_exp]

    b_ov = ((baseline.get("posture") or {}).get("overall") or {})
    c_ov = ((current.get("posture") or {}).get("overall") or {})
    b_score = b_ov.get("score")
    c_score = c_ov.get("score")
    score_delta = (c_score - b_score) if (isinstance(b_score, (int, float)) and isinstance(c_score, (int, float))) else None

    return {
        "baseline_run_id": baseline.get("run_id"),
        "baseline_target": baseline.get("company"),
        "current_run_id": current.get("run_id"),
        "current_target": current.get("company"),
        "summary": {
            "added_count": len(added_keys),
            "removed_count": len(removed_keys),
            "added_facts_count": len(added_keys),
            "removed_facts_count": len(removed_keys),
            "unchanged_facts_count": unchanged_count,
            "added_hosts_count": len(added_geo),
            "removed_hosts_count": len(removed_geo),
            "modified_hosts_count": len(host_changes),
            "new_exposures_count": len(new_exposures),
            "resolved_exposures_count": len(resolved_exposures),
            "posture_score_delta": score_delta,
            "score_delta": score_delta,
            "baseline_grade": b_ov.get("letter") or "N/A",
            "current_grade": c_ov.get("letter") or "N/A",
        },
        "posture_delta": {
            "baseline_letter": b_ov.get("letter") or "N/A",
            "baseline_score": b_score,
            "current_letter": c_ov.get("letter") or "N/A",
            "current_score": c_score,
            "delta": score_delta,
        },
        "added_facts": added_facts,
        "removed_facts": removed_facts,
        "added_geo_points": added_geo,
        "removed_geo_points": removed_geo,
        "host_changes": host_changes,
        "host_port_drift": host_changes,
        "new_exposures": new_exposures,
        "resolved_exposures": resolved_exposures,
    }


class OperationsManager:
    """Thread-safe local persistence for Cases, Pins, Analyst Notes, and ACH Matrices."""

    def __init__(self, store_path: Path):
        self.store_path = store_path
        self.lock = threading.Lock()

    def _load(self) -> dict[str, Any]:
        default_state = {
            "cases": [],
            "pins": [],
            "notes": [],
            "hypotheses": [],
            "imported_briefs": {},
            "webhook": {"url_masked": "", "url": "", "kind": "slack", "enabled": False},
        }
        if not self.store_path.exists():
            return default_state
        try:
            if self.store_path.is_symlink():
                return default_state
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return default_state
            wh = data.get("webhook") if isinstance(data.get("webhook"), dict) else {}
            wh_url = str(wh.get("url") or "").strip()
            return {
                "cases": list(data.get("cases") or []),
                "pins": list(data.get("pins") or []),
                "notes": list(data.get("notes") or []),
                "hypotheses": list(data.get("hypotheses") or []),
                "imported_briefs": dict(data.get("imported_briefs") or {}),
                "webhook": {
                    "url": wh_url,
                    "url_masked": ("••••" + wh_url[-12:]) if len(wh_url) > 12 else ("••••" if wh_url else ""),
                    "kind": str(wh.get("kind") or "slack"),
                    "enabled": bool(wh.get("enabled") and wh_url),
                },
            }
        except Exception:
            return default_state

    def _save(self, data: dict[str, Any]) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        harden_path(self.store_path.parent)
        tmp = self.store_path.with_suffix(".json.tmp")
        if tmp.is_symlink():
            raise ValueError("Operations storage must not contain symbolic links.")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        tmp.replace(self.store_path)
        harden_path(self.store_path)

    def snapshot(self, run_id: str | None = None) -> dict[str, Any]:
        with self.lock:
            data = self._load()
        wh_kind = data["webhook"].get("provider") or data["webhook"].get("kind") or "slack"
        wh_public = {
            "configured": bool(data["webhook"].get("url")),
            "url": data["webhook"].get("url") or "",
            "url_masked": data["webhook"].get("url_masked") or "",
            "kind": wh_kind,
            "provider": wh_kind,
            "enabled": bool(data["webhook"].get("enabled")),
        }
        if not run_id:
            return {
                "cases": data["cases"],
                "pins": data["pins"],
                "notes": data["notes"],
                "hypotheses": data["hypotheses"],
                "webhook": wh_public,
            }
        return {
            "cases": data["cases"],
            "pins": [p for p in data["pins"] if p.get("run_id") == run_id or p.get("global")],
            "notes": [n for n in data["notes"] if n.get("run_id") == run_id],
            "hypotheses": [h for h in data["hypotheses"] if h.get("run_id") == run_id],
            "webhook": wh_public,
        }

    def get_imported_brief(self, run_id: str) -> dict[str, Any] | None:
        with self.lock:
            data = self._load()
            b = (data.get("imported_briefs") or {}).get(run_id)
            return dict(b) if isinstance(b, dict) else None

    def save_case(self, payload: dict[str, Any]) -> dict[str, Any]:
        name = str(payload.get("name") or payload.get("title") or "").strip()[:120]
        if not name:
            raise ValueError("Enter an operation case name.")
        objective = str(payload.get("objective") or payload.get("client") or "").strip()[:400]
        classification = str(payload.get("classification") or "TLP:AMBER").strip()[:32]
        if classification not in ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"):
            classification = "TLP:AMBER"
        raw_runs = payload.get("run_ids") or []
        if not isinstance(raw_runs, list):
            raise ValueError("run_ids must be a list of run identifiers.")
        run_ids: list[str] = []
        for r in raw_runs[:50]:
            rid = str(r or "").strip()
            if len(rid) == 32 and all(c in "0123456789abcdef" for c in rid) and rid not in run_ids:
                run_ids.append(rid)

        case_id = str(payload.get("id") or "").strip()
        with self.lock:
            data = self._load()
            cases = data["cases"]
            existing = next((c for c in cases if c.get("id") == case_id), None) if case_id else None
            if existing:
                existing["name"] = name
                existing["title"] = name
                existing["objective"] = objective
                existing["client"] = objective
                existing["classification"] = classification
                existing["run_ids"] = run_ids
                existing["updated_at"] = _now_iso()
                saved = existing
            else:
                if len(cases) >= 100:
                    raise ValueError("Maximum number of operation cases (100) reached.")
                saved = {
                    "id": uuid4().hex[:16],
                    "name": name,
                    "title": name,
                    "objective": objective,
                    "client": objective,
                    "classification": classification,
                    "run_ids": run_ids,
                    "created_at": _now_iso(),
                    "updated_at": _now_iso(),
                }
                cases.insert(0, saved)
            self._save(data)
        return {"case": saved, "cases": data["cases"], "operations": self.snapshot()}

    def delete_case(self, case_id: str) -> dict[str, Any]:
        cid = str(case_id or "").strip()
        with self.lock:
            data = self._load()
            data["cases"] = [c for c in data["cases"] if c.get("id") != cid]
            self._save(data)
        return {"cases": data["cases"], "operations": self.snapshot()}

    def toggle_pin(self, payload: dict[str, Any]) -> dict[str, Any]:
        run_id = str(payload.get("run_id") or "").strip()
        key = str(payload.get("key") or payload.get("fact_id") or "").strip()[:160]
        if not key:
            raise ValueError("Pin key or fact_id is required.")
        subject = str(payload.get("subject") or "").strip()[:160]
        attribute = str(payload.get("attribute") or payload.get("label") or key).strip()[:160]
        label = str(payload.get("label") or attribute or key).strip()[:200]
        value = str(payload.get("value") or "").strip()[:500]
        source = str(payload.get("source") or "find3r").strip()[:80]
        admiralty = str(payload.get("admiralty") or "C3").strip()[:8]
        note = str(payload.get("note") or "").strip()[:400]

        with self.lock:
            data = self._load()
            pins = data["pins"]
            existing_idx = next(
                (i for i, p in enumerate(pins) if (p.get("key") == key or p.get("fact_id") == key) and p.get("run_id") == run_id),
                None,
            )
            if existing_idx is not None and not payload.get("force_update"):
                pins.pop(existing_idx)
                pinned = False
            elif existing_idx is not None:
                pins[existing_idx]["note"] = note
                pinned = True
            else:
                if len(pins) >= 500:
                    pins.pop()
                pins.insert(0, {
                    "id": uuid4().hex[:16],
                    "run_id": run_id,
                    "key": key,
                    "fact_id": key,
                    "subject": subject,
                    "attribute": attribute,
                    "label": label,
                    "value": value,
                    "source": source,
                    "admiralty": admiralty,
                    "note": note,
                    "created_at": _now_iso(),
                })
                pinned = True
            self._save(data)
        return {
            "pinned": pinned,
            "pins": [p for p in data["pins"] if not run_id or p.get("run_id") == run_id],
            "operations": self.snapshot(),
        }

    def add_note(self, payload: dict[str, Any]) -> dict[str, Any]:
        run_id = str(payload.get("run_id") or "").strip()
        subject = str(payload.get("subject") or "general").strip()[:180]
        author = str(payload.get("author") or "local-analyst").strip()[:80]
        classification = str(payload.get("classification") or "TLP:AMBER+STRICT").strip()[:32]
        text_val = str(payload.get("text") or payload.get("body") or "").strip()[:1000]
        tag = str(payload.get("tag") or "OBSERVATION").strip().upper()[:32]
        if not text_val:
            raise ValueError("Enter an analyst note before saving.")
        with self.lock:
            data = self._load()
            notes = data["notes"]
            if len(notes) >= 500:
                notes.pop()
            entry = {
                "id": uuid4().hex[:16],
                "run_id": run_id,
                "subject": subject,
                "author": author,
                "classification": classification,
                "tag": tag,
                "text": text_val,
                "body": text_val,
                "created_at": _now_iso(),
            }
            notes.insert(0, entry)
            self._save(data)
        return {
            "note": entry,
            "notes": [n for n in data["notes"] if not run_id or n.get("run_id") == run_id],
            "operations": self.snapshot(),
        }

    def delete_note(self, note_id: str, run_id: str = "") -> dict[str, Any]:
        nid = str(note_id or "").strip()
        with self.lock:
            data = self._load()
            data["notes"] = [n for n in data["notes"] if n.get("id") != nid]
            self._save(data)
        return {
            "notes": [n for n in data["notes"] if not run_id or n.get("run_id") == run_id],
            "operations": self.snapshot(),
        }

    def save_hypothesis(self, payload: dict[str, Any], facts: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        run_id = str(payload.get("run_id") or "").strip()
        title = str(payload.get("title") or "").strip()[:160]
        if not title:
            raise ValueError("Enter a hypothesis statement.")
        description = str(payload.get("description") or "").strip()[:500]
        raw_ratings = payload.get("ratings") if isinstance(payload.get("ratings"), dict) else {}
        ratings: dict[str, str] = {}
        for fid, status in raw_ratings.items():
            if status in ("consistent", "inconsistent", "neutral") and _ID_RE.fullmatch(str(fid)):
                ratings[str(fid)] = str(status)
        supporting_attrs = [
            str(s).strip()[:80]
            for s in (payload.get("supporting_attributes") or [])
            if str(s).strip()
        ][:20]
        refuting_attrs = [
            str(s).strip()[:80]
            for s in (payload.get("refuting_attributes") or [])
            if str(s).strip()
        ][:20]

        hyp_id = str(payload.get("id") or "").strip()
        with self.lock:
            data = self._load()
            hyps = data["hypotheses"]
            existing = next((h for h in hyps if h.get("id") == hyp_id), None) if hyp_id else None
            if existing:
                existing["title"] = title
                existing["description"] = description
                existing["ratings"] = ratings
                existing["supporting_attributes"] = supporting_attrs
                existing["refuting_attributes"] = refuting_attrs
                existing["updated_at"] = _now_iso()
            else:
                if len(hyps) >= 200:
                    hyps.pop()
                hyps.append({
                    "id": uuid4().hex[:16],
                    "run_id": run_id,
                    "title": title,
                    "description": description,
                    "ratings": ratings,
                    "supporting_attributes": supporting_attrs,
                    "refuting_attributes": refuting_attrs,
                    "created_at": _now_iso(),
                    "updated_at": _now_iso(),
                })
            self._save(data)
        run_hyps = [h for h in data["hypotheses"] if not run_id or h.get("run_id") == run_id]
        scored = self.score_hypotheses(run_hyps, facts or [])
        snap = self.snapshot()
        snap["ach_ranked"] = scored
        return {"hypotheses": scored, "operations": snap}

    def delete_hypothesis(self, hyp_id: str, run_id: str = "", facts: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        hid = str(hyp_id or "").strip()
        with self.lock:
            data = self._load()
            data["hypotheses"] = [h for h in data["hypotheses"] if h.get("id") != hid]
            self._save(data)
        run_hyps = [h for h in data["hypotheses"] if not run_id or h.get("run_id") == run_id]
        scored = self.score_hypotheses(run_hyps, facts or [])
        snap = self.snapshot()
        snap["ach_ranked"] = scored
        return {"hypotheses": scored, "operations": snap}

    @staticmethod
    def score_hypotheses(hypotheses: list[dict[str, Any]], facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Score each ACH hypothesis using Admiralty-grade reliability weights."""
        fact_by_id = {str(f.get("fact_id")): f for f in facts if isinstance(f, dict) and f.get("fact_id")}
        scored: list[dict[str, Any]] = []
        for h in hypotheses:
            ratings = h.get("ratings") if isinstance(h.get("ratings"), dict) else {}
            supp_attrs = [str(x).lower() for x in (h.get("supporting_attributes") or [])]
            ref_attrs = [str(x).lower() for x in (h.get("refuting_attributes") or [])]
            support_score = 0
            contradict_score = 0
            support_count = 0
            contradict_count = 0
            supporting_fact_ids: list[str] = []
            for fid, stance in ratings.items():
                f = fact_by_id.get(fid)
                grade = str((f or {}).get("admiralty") or "C3").upper()
                w = ADMIRALTY_WEIGHTS.get(grade, 2)
                if stance == "consistent":
                    support_score += w
                    support_count += 1
                    supporting_fact_ids.append(fid)
                elif stance == "inconsistent":
                    contradict_score += w * 2
                    contradict_count += 1
            for f in facts:
                fid = str(f.get("fact_id") or "")
                if fid in ratings:
                    continue
                attr_l = str(f.get("attribute") or "").lower()
                val_l = str(f.get("value") or "").lower()
                grade = str(f.get("admiralty") or "C3").upper()
                w = ADMIRALTY_WEIGHTS.get(grade, 2)
                if any(tok and (tok in attr_l or tok in val_l) for tok in supp_attrs):
                    support_score += w
                    support_count += 1
                    if fid:
                        supporting_fact_ids.append(fid)
                elif any(tok and (tok in attr_l or tok in val_l) for tok in ref_attrs):
                    contradict_score += w * 2
                    contradict_count += 1

            net_score = support_score - contradict_score
            if contradict_count > 0 and contradict_score >= support_score:
                verdict = "REFUTED / HIGH INCONSISTENCY"
            elif support_count > 0 and contradict_count == 0:
                verdict = "STRONGLY SUPPORTED"
            elif support_count > 0:
                verdict = "CONTESTED / PARTIAL SUPPORT"
            else:
                verdict = "UNASSESSED"
            total_w = support_score + contradict_score
            conf_pct = round((support_score / total_w) * 100) if total_w > 0 else 50
            scored.append({
                **h,
                "support_score": support_score,
                "contradict_score": contradict_score,
                "refute_score": contradict_score,
                "net_score": net_score,
                "support_count": support_count,
                "supporting_count": support_count,
                "contradict_count": contradict_count,
                "refuting_count": contradict_count,
                "supporting_fact_ids": supporting_fact_ids[:12],
                "confidence_pct": conf_pct,
                "verdict": verdict,
                "assessment": verdict,
            })
        return sorted(scored, key=lambda item: (-item["net_score"], item["contradict_score"]))

    def build_case_dossier(self, case_id: str, brief_loader: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
        """Fuse all runs in an Operation Case into a unified multi-target intelligence brief."""
        cid = str(case_id or "").strip()
        with self.lock:
            data = self._load()
        case = next((c for c in data["cases"] if c.get("id") == cid), None)
        if not case:
            raise ValueError("Operation case not found.")

        fused_facts: list[dict[str, Any]] = []
        seen_fact_keys: set[tuple[str, str, str, str]] = set()
        value_to_targets: dict[tuple[str, str], set[str]] = {}
        run_summaries: list[dict[str, Any]] = []

        for rid in case.get("run_ids") or []:
            try:
                b = brief_loader(rid)
            except Exception:
                imp = (data.get("imported_briefs") or {}).get(rid)
                if isinstance(imp, dict):
                    b = imp
                else:
                    continue
            target = str(b.get("company") or rid)
            run_summaries.append({
                "run_id": rid,
                "target": target,
                "subject_kind": b.get("subject_kind") or "domain",
                "facts_count": len(b.get("facts") or []),
                "posture_letter": ((b.get("posture") or {}).get("overall") or {}).get("letter") or "N/A",
            })
            for f in b.get("facts") or []:
                attr = str(f.get("attribute") or "")
                val = str(f.get("value") or "").strip()
                subj = str(f.get("subject") or target).strip()
                src = str(f.get("source") or "find3r")
                if not val:
                    continue
                if attr in (
                    "dns.a", "dns.aaaa", "dns.passive.ipv4", "dns.passive.ipv6",
                    "dns.mx", "dns.ns", "host.asn", "host.org", "tls.ct.issuer",
                    "whois.registrar", "company.business_email", "person.business_email",
                    "public.account.url", "host.vuln", "bgp.prefix",
                ):
                    value_to_targets.setdefault((attr, val), set()).add(target)
                fkey = (subj.lower(), attr, val, src)
                if fkey not in seen_fact_keys:
                    seen_fact_keys.add(fkey)
                    fused_facts.append(f)

        correlations: list[dict[str, Any]] = []
        for (attr, val), targets in value_to_targets.items():
            if len(targets) >= 2:
                correlations.append({
                    "attribute": attr,
                    "value": val,
                    "shared_targets": sorted(targets),
                    "targets": sorted(targets),
                    "target_count": len(targets),
                })
        correlations.sort(key=lambda item: (-item["target_count"], item["attribute"], item["value"]))

        case_label = case.get("name") or case.get("title") or "Operation Case"
        posture = grade_brief_posture(fused_facts)
        return {
            "run_id": f"case-{cid}",
            "company": case_label,
            "subject_kind": "company",
            "status": "complete",
            "stop_reason": f"Fused {len(run_summaries)} runs",
            "case": case,
            "runs": run_summaries,
            "runs_count": len(run_summaries),
            "correlations": correlations[:60],
            "shared_correlations": correlations[:60],
            "total_facts": len(fused_facts),
            "posture": posture,
            "exposures": posture["exposures"],
            "graph": build_graph(case_label, fused_facts, subject_kind="company"),
            "geo_map": build_geo_map(case_label, fused_facts, subject_kind="company"),
            "facts": fused_facts[:400],
            "inferences": [],
            "requirements": [],
            "skipped": [],
            "collection": [],
        }

    def export_case_bundle(self, case_id: str, brief_loader: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
        """Export a portable .find3r-case.json bundle for partner/team sharing."""
        import hashlib

        cid = str(case_id or "").strip()
        with self.lock:
            data = self._load()
        case = next((c for c in data["cases"] if c.get("id") == cid), None)
        if not case:
            raise ValueError("Operation case not found.")

        run_ids = list(case.get("run_ids") or [])
        included_briefs: dict[str, dict[str, Any]] = {}
        for rid in run_ids:
            try:
                included_briefs[rid] = brief_loader(rid)
            except Exception:
                imp = (data.get("imported_briefs") or {}).get(rid)
                if isinstance(imp, dict):
                    included_briefs[rid] = imp

        case_pins = [p for p in data["pins"] if p.get("run_id") in run_ids or not p.get("run_id")]
        case_notes = [n for n in data["notes"] if n.get("run_id") in run_ids or not n.get("run_id")]
        case_hyps = [h for h in data["hypotheses"] if h.get("run_id") in run_ids or not h.get("run_id")]

        payload = {
            "format": "find3r.case.bundle.v1",
            "exported_at": _now_iso(),
            "case": case,
            "briefs": included_briefs,
            "pins": case_pins[:200],
            "notes": case_notes[:200],
            "hypotheses": case_hyps[:100],
        }
        canonical_bytes = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        payload["bundle_sha256"] = hashlib.sha256(canonical_bytes).hexdigest()
        return payload

    def import_case_bundle(self, bundle: dict[str, Any]) -> dict[str, Any]:
        """Import a partner's .find3r-case.json bundle into the active workspace."""
        if not isinstance(bundle, dict) or bundle.get("format") != "find3r.case.bundle.v1":
            raise ValueError("Invalid case bundle format (expected find3r.case.bundle.v1).")
        case_in = bundle.get("case")
        if not isinstance(case_in, dict) or not (case_in.get("name") or case_in.get("title")):
            raise ValueError("Case bundle is missing valid case metadata.")

        title = str(case_in.get("name") or case_in.get("title")).strip()[:120]
        client_tag = str(case_in.get("objective") or case_in.get("client") or "").strip()[:400]
        classification = str(case_in.get("classification") or "TLP:AMBER").strip()[:32]
        raw_runs = case_in.get("run_ids") if isinstance(case_in.get("run_ids"), list) else []
        run_ids = [
            str(r).strip()
            for r in raw_runs[:50]
            if len(str(r).strip()) == 32 and all(c in "0123456789abcdef" for c in str(r).strip())
        ]

        with self.lock:
            data = self._load()
            cid = str(case_in.get("id") or "").strip()[:32] or uuid4().hex[:16]
            existing = next((c for c in data["cases"] if c.get("id") == cid), None)
            saved_case = {
                "id": cid,
                "name": title,
                "title": title,
                "objective": client_tag,
                "client": client_tag,
                "classification": classification,
                "run_ids": run_ids,
                "created_at": str(case_in.get("created_at") or _now_iso()),
                "updated_at": _now_iso(),
            }
            if existing:
                existing.update(saved_case)
            else:
                data["cases"].insert(0, saved_case)

            # Store imported briefs so they can be fused and inspected even if not in local SQLite
            briefs_in = bundle.get("briefs") if isinstance(bundle.get("briefs"), dict) else {}
            imp_store = data.setdefault("imported_briefs", {})
            imported_runs_count = 0
            for rid, b_obj in list(briefs_in.items())[:50]:
                if len(str(rid)) == 32 and isinstance(b_obj, dict):
                    imp_store[str(rid)] = b_obj
                    imported_runs_count += 1

            # Merge pins, notes, and hypotheses without duplicating IDs
            existing_pin_ids = {p.get("id") for p in data["pins"]}
            imported_pins_count = 0
            for p in (bundle.get("pins") or [])[:200]:
                if isinstance(p, dict) and p.get("id") not in existing_pin_ids:
                    data["pins"].append(p)
                    existing_pin_ids.add(p.get("id"))
                    imported_pins_count += 1

            existing_note_ids = {n.get("id") for n in data["notes"]}
            imported_notes_count = 0
            for n in (bundle.get("notes") or [])[:200]:
                if isinstance(n, dict) and n.get("id") not in existing_note_ids:
                    data["notes"].append(n)
                    existing_note_ids.add(n.get("id"))
                    imported_notes_count += 1

            existing_hyp_ids = {h.get("id") for h in data["hypotheses"]}
            for h in (bundle.get("hypotheses") or [])[:100]:
                if isinstance(h, dict) and h.get("id") not in existing_hyp_ids:
                    data["hypotheses"].append(h)
                    existing_hyp_ids.add(h.get("id"))

            self._save(data)
        return {
            "imported": {
                "case_id": cid,
                "case_title": title,
                "imported_runs": imported_runs_count,
                "imported_pins": imported_pins_count,
                "imported_notes": imported_notes_count,
            },
            "imported_case": saved_case,
            "imported_runs_count": imported_runs_count,
            "operations": self.snapshot(),
        }

    def save_webhook(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Configure a Slack, Discord, or Generic HTTPS Webhook for team & delta alerts."""
        import ipaddress
        from urllib.parse import urlparse

        url = str(payload.get("url") or "").strip()
        kind = str(payload.get("provider") or payload.get("kind") or "slack").strip().lower()
        if kind not in ("slack", "discord", "generic"):
            kind = "slack"
        enabled = bool(payload.get("enabled", True))

        if url:
            parsed = urlparse(url)
            if parsed.scheme != "https" or not parsed.hostname:
                raise ValueError("Webhook URL must use HTTPS and a valid hostname.")
            try:
                ip = ipaddress.ip_address(parsed.hostname)
                if not ip.is_global:
                    raise ValueError("Webhook URL must target a globally routable host.")
            except ValueError as exc:
                if "globally routable" in str(exc):
                    raise
                if parsed.hostname.lower() in ("localhost", "localhost.localdomain"):
                    raise ValueError("Webhook URL cannot target localhost.") from None

        with self.lock:
            data = self._load()
            data["webhook"] = {
                "url": url,
                "kind": kind,
                "provider": kind,
                "enabled": bool(enabled and url),
            }
            self._save(data)
        return {"webhook": self.snapshot()["webhook"], "operations": self.snapshot()}

    def send_webhook_alert(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a real-time alert to the configured team webhook (Slack/Discord/Generic)."""
        import ipaddress
        import socket
        import urllib.request
        from urllib.parse import urlparse
        from neesha.collectors.network import _default_context
        from neesha.runtime.providers import _NoRedirect

        with self.lock:
            data = self._load()
            wh = data.get("webhook") or {}
        url = str(payload.get("url") or wh.get("url") or "").strip()
        kind = str(payload.get("provider") or payload.get("kind") or wh.get("provider") or wh.get("kind") or "slack").strip().lower()
        if not url:
            return {"sent": False, "error": "Configure an HTTPS Webhook URL first."}

        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            return {"sent": False, "error": "Webhook URL must use HTTPS."}
        try:
            infos = socket.getaddrinfo(parsed.hostname, 443, proto=socket.IPPROTO_TCP)
            for info in infos:
                if not ipaddress.ip_address(info[4][0]).is_global:
                    return {"sent": False, "error": "Webhook hostname resolved to a non-global IP address."}
        except Exception as exc:
            return {"sent": False, "error": f"Could not resolve webhook host: {exc}"}

        title = str(payload.get("title") or "Find3r Intelligence Alert").strip()[:200]
        summary = str(payload.get("summary") or "New operational event or attack-surface delta recorded.").strip()[:1500]
        msg_text = f"*{title}*\n{summary}"

        if kind == "slack":
            body = json.dumps({"text": msg_text}).encode("utf-8")
        elif kind == "discord":
            body = json.dumps({"content": msg_text}).encode("utf-8")
        else:
            body = json.dumps({
                "event": "find3r.alert",
                "timestamp": _now_iso(),
                "title": title,
                "summary": summary,
            }).encode("utf-8")

        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=_default_context()),
            _NoRedirect(),
        )
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "Find3r-Webhook/0.2"},
        )
        try:
            with opener.open(req, timeout=10) as resp:
                status = getattr(resp, "status", 200)
        except Exception as exc:
            raise ValueError(f"Webhook delivery failed: {exc}") from exc
        return {"sent": True, "http_status": status, "kind": kind}

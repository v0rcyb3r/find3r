"""Geospatial infrastructure mapping and Maltego entity/transform interoperability.

Builds an offline-capable Geo-IP & ASN topology map from guarded investigation facts
(combining Shodan / Geo-IP coordinates with country and cloud-backbone centroids)
and exports investigation graphs to Maltego GraphML (.graphml), Maltego CSV (.csv),
and Maltego Local Transform XML.
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import math
import re
from typing import Any
from xml.sax.saxutils import escape as _sax_escape

_XML_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _xml_escape(val: Any) -> str:
    cleaned = _XML_CTRL_RE.sub("", str(val or ""))
    return _sax_escape(cleaned, {'"': "&quot;", "'": "&apos;"})

# ISO-3166-1 alpha-2 country centroids (lat, lon, display name)
COUNTRY_CENTROIDS: dict[str, tuple[float, float, str]] = {
    "US": (37.77, -97.00, "United States"),
    "CA": (45.42, -75.69, "Canada"),
    "MX": (19.43, -99.13, "Mexico"),
    "BR": (-23.55, -46.63, "Brazil"),
    "AR": (-34.60, -58.38, "Argentina"),
    "CL": (-33.45, -70.67, "Chile"),
    "CO": (4.71, -74.07, "Colombia"),
    "GB": (51.51, -0.13, "United Kingdom"),
    "IE": (53.35, -6.26, "Ireland"),
    "FR": (48.86, 2.35, "France"),
    "DE": (50.11, 8.68, "Germany"),
    "NL": (52.37, 4.90, "Netherlands"),
    "BE": (50.85, 4.35, "Belgium"),
    "LU": (49.61, 6.13, "Luxembourg"),
    "CH": (47.37, 8.54, "Switzerland"),
    "AT": (48.21, 16.37, "Austria"),
    "ES": (40.42, -3.70, "Spain"),
    "PT": (38.72, -9.14, "Portugal"),
    "IT": (45.46, 9.19, "Italy"),
    "SE": (59.33, 18.07, "Sweden"),
    "NO": (59.91, 10.75, "Norway"),
    "FI": (60.17, 24.94, "Finland"),
    "DK": (55.68, 12.57, "Denmark"),
    "IS": (64.15, -21.94, "Iceland"),
    "PL": (52.23, 21.01, "Poland"),
    "CZ": (50.08, 14.44, "Czechia"),
    "RO": (44.43, 26.10, "Romania"),
    "BG": (42.70, 23.32, "Bulgaria"),
    "HU": (47.50, 19.04, "Hungary"),
    "GR": (37.98, 23.73, "Greece"),
    "UA": (50.45, 30.52, "Ukraine"),
    "TR": (41.01, 28.98, "Turkey"),
    "IL": (32.09, 34.78, "Israel"),
    "AE": (25.20, 55.27, "United Arab Emirates"),
    "SA": (24.71, 46.68, "Saudi Arabia"),
    "ZA": (-26.20, 28.05, "South Africa"),
    "NG": (6.52, 3.38, "Nigeria"),
    "KE": (-1.29, 36.82, "Kenya"),
    "EG": (30.04, 31.24, "Egypt"),
    "IN": (19.08, 72.88, "India"),
    "SG": (1.35, 103.82, "Singapore"),
    "MY": (3.14, 101.69, "Malaysia"),
    "ID": (-6.21, 106.85, "Indonesia"),
    "TH": (13.76, 100.50, "Thailand"),
    "VN": (21.03, 105.85, "Vietnam"),
    "PH": (14.60, 120.98, "Philippines"),
    "HK": (22.32, 114.17, "Hong Kong"),
    "TW": (25.03, 121.57, "Taiwan"),
    "CN": (39.90, 116.41, "China"),
    "KR": (37.57, 126.98, "South Korea"),
    "JP": (35.68, 139.77, "Japan"),
    "AU": (-33.87, 151.21, "Australia"),
    "NZ": (-36.85, 174.76, "New Zealand"),
    "RU": (55.76, 37.62, "Russia"),
}

# Well-known cloud / CDN prefix hints when RDAP/Shodan country is not yet populated
KNOWN_NETWORK_HINTS: tuple[tuple[str, str, str, float, float, str], ...] = (
    ("104.16.", "Cloudflare, Inc.", "AS13335", 37.77, -122.42, "US"),
    ("104.17.", "Cloudflare, Inc.", "AS13335", 37.77, -122.42, "US"),
    ("104.18.", "Cloudflare, Inc.", "AS13335", 37.77, -122.42, "US"),
    ("104.21.", "Cloudflare, Inc.", "AS13335", 37.77, -122.42, "US"),
    ("172.64.", "Cloudflare, Inc.", "AS13335", 37.77, -122.42, "US"),
    ("172.67.", "Cloudflare, Inc.", "AS13335", 37.77, -122.42, "US"),
    ("1.1.1.", "Cloudflare DNS", "AS13335", -33.87, 151.21, "AU"),
    ("8.8.8.", "Google Cloud / DNS", "AS15169", 37.39, -122.08, "US"),
    ("8.8.4.", "Google Cloud / DNS", "AS15169", 37.39, -122.08, "US"),
    ("142.250.", "Google LLC", "AS15169", 37.39, -122.08, "US"),
    ("34.", "Google Cloud Platform", "AS15169", 37.39, -122.08, "US"),
    ("35.", "Google Cloud Platform", "AS15169", 37.39, -122.08, "US"),
    ("52.", "Amazon Web Services (AWS)", "AS16509", 39.04, -77.49, "US"),
    ("54.", "Amazon Web Services (AWS)", "AS16509", 39.04, -77.49, "US"),
    ("3.", "Amazon Web Services (AWS)", "AS16509", 39.04, -77.49, "US"),
    ("13.", "Amazon CloudFront / AWS", "AS16509", 39.04, -77.49, "US"),
    ("18.", "Amazon Web Services (AWS)", "AS16509", 39.04, -77.49, "US"),
    ("151.101.", "Fastly CDN", "AS54113", 37.77, -122.42, "US"),
    ("199.232.", "Fastly CDN", "AS54113", 37.77, -122.42, "US"),
    ("185.199.", "GitHub Pages / Fastly", "AS54113", 37.77, -122.42, "US"),
    ("140.82.", "GitHub, Inc.", "AS36459", 37.77, -122.42, "US"),
    ("20.", "Microsoft Azure", "AS8075", 47.64, -122.13, "US"),
    ("40.", "Microsoft Azure", "AS8075", 47.64, -122.13, "US"),
    ("93.184.215.", "Edgecast / IANA Reserved", "AS15133", 34.05, -118.24, "US"),
    ("93.184.216.", "Edgecast / IANA Reserved", "AS15133", 34.05, -118.24, "US"),
    ("116.202.", "Hetzner Online GmbH", "AS24940", 50.11, 8.68, "DE"),
    ("116.203.", "Hetzner Online GmbH", "AS24940", 50.11, 8.68, "DE"),
    ("138.201.", "Hetzner Online GmbH", "AS24940", 50.11, 8.68, "DE"),
    ("51.38.", "OVHcloud", "AS16276", 48.86, 2.35, "FR"),
    ("51.68.", "OVHcloud", "AS16276", 48.86, 2.35, "FR"),
    ("76.76.21.", "Vercel Edge Network", "AS16509", 37.77, -122.42, "US"),
)

MALTEGO_ENTITY_MAP: dict[str, str] = {
    "organization": "maltego.Company",
    "company": "maltego.Company",
    "domain": "maltego.Domain",
    "subdomain": "maltego.DNSName",
    "hostname": "maltego.DNSName",
    "ip": "maltego.IPv4Address",
    "email": "maltego.EmailAddress",
    "email_subject": "maltego.EmailAddress",
    "username": "maltego.Alias",
    "username_subject": "maltego.Alias",
    "account": "maltego.Alias",
    "person": "maltego.Person",
    "person_subject": "maltego.Person",
    "phone": "maltego.PhoneNumber",
    "phone_subject": "maltego.PhoneNumber",
    "certificate_issuer": "maltego.SSL",
    "port": "maltego.Port",
    "vulnerability": "maltego.Vulnerability",
    "url": "maltego.URL",
}


def _project_svg(lat: float, lon: float, width: float = 1000.0, height: float = 500.0) -> tuple[float, float]:
    """Project (lat, lon) onto a 1000x500 equirectangular SVG map canvas."""
    clamped_lat = max(-82.0, min(82.0, float(lat)))
    clamped_lon = max(-180.0, min(180.0, float(lon)))
    x = round(((clamped_lon + 180.0) / 360.0) * width, 1)
    y = round(((90.0 - clamped_lat) / 180.0) * height, 1)
    return x, y


def _jitter_coords(seed_key: str, lat: float, lon: float) -> tuple[float, float]:
    """Apply subtle deterministic offset when multiple IPs share a country centroid."""
    digest = hashlib.sha256(seed_key.encode("utf-8")).digest()
    dlat = ((digest[0] / 255.0) - 0.5) * 2.4
    dlon = ((digest[1] / 255.0) - 0.5) * 3.6
    return round(lat + dlat, 4), round(lon + dlon, 4)


def _is_valid_ip(val: str) -> bool:
    try:
        ipaddress.ip_address(val.strip())
        return True
    except ValueError:
        return False


def build_geo_map(company: str, facts: list[dict], subject_kind: str = "company") -> dict[str, Any]:
    """Construct a geospatial infrastructure & ASN map from guarded investigation facts."""
    ip_records: dict[str, dict[str, Any]] = {}
    domain_country: str | None = None
    domain_org: str | None = None

    def ensure_ip(ip_val: str) -> dict[str, Any]:
        ip_clean = ip_val.strip()
        if ip_clean not in ip_records:
            ip_records[ip_clean] = {
                "ip": ip_clean,
                "hostnames": set(),
                "ports": set(),
                "vulns": set(),
                "cpes": set(),
                "tags": set(),
                "country": None,
                "city": None,
                "lat": None,
                "lon": None,
                "org": None,
                "asn": None,
                "cidr": None,
                "fact_ids": [],
            }
        return ip_records[ip_clean]

    if subject_kind == "ip" and _is_valid_ip(company):
        ensure_ip(company)

    for f in facts:
        attr = f.get("attribute") or ""
        val = (f.get("value") or "").strip()
        subj = (f.get("subject") or "").strip()
        fid = f.get("fact_id")
        if not val:
            continue

        if attr == "whois.country" and len(val) == 2:
            domain_country = val.upper()
        elif attr == "whois.org" and not domain_org:
            domain_org = val

        if attr in ("dns.a", "dns.aaaa", "dns.passive.ipv4", "dns.passive.ipv6") and _is_valid_ip(val):
            rec = ensure_ip(val)
            if subj and not _is_valid_ip(subj):
                rec["hostnames"].add(subj)
            if fid and fid not in rec["fact_ids"]:
                rec["fact_ids"].append(fid)
        elif _is_valid_ip(subj):
            rec = ensure_ip(subj)
            if fid and fid not in rec["fact_ids"]:
                rec["fact_ids"].append(fid)
            if attr == "host.port":
                rec["ports"].add(val)
            elif attr == "host.vuln":
                rec["vulns"].add(val)
            elif attr == "host.cpe":
                rec["cpes"].add(val)
            elif attr == "host.reverse_dns":
                rec["hostnames"].add(val)
            elif attr == "host.tag":
                rec["tags"].add(val)
            elif attr == "host.country" and len(val) >= 2:
                rec["country"] = val[:2].upper()
            elif attr == "host.city":
                rec["city"] = val
            elif attr == "host.latitude":
                try:
                    lat_f = float(val)
                    if math.isfinite(lat_f) and -90.0 <= lat_f <= 90.0:
                        rec["lat"] = lat_f
                except ValueError:
                    pass
            elif attr == "host.longitude":
                try:
                    lon_f = float(val)
                    if math.isfinite(lon_f) and -180.0 <= lon_f <= 180.0:
                        rec["lon"] = lon_f
                except ValueError:
                    pass
            elif attr in ("host.org", "host.isp") and not rec["org"]:
                rec["org"] = val
            elif attr in ("host.asn", "host.asn_name") and not rec["asn"]:
                rec["asn"] = val
            elif attr == "host.cidr":
                rec["cidr"] = val

    points: list[dict[str, Any]] = []
    country_counts: dict[str, int] = {}
    provider_counts: dict[str, int] = {}
    all_ports: set[str] = set()
    vuln_nodes = 0

    for ip_str, rec in sorted(ip_records.items()):
        lat = rec["lat"]
        lon = rec["lon"]
        cc = rec["country"]
        org = rec["org"]
        asn = rec["asn"]
        city = rec["city"]

        # Check known network prefix hints before falling back to target domain WHOIS
        for prefix, hint_org, hint_asn, h_lat, h_lon, h_cc in KNOWN_NETWORK_HINTS:
            if ip_str.startswith(prefix):
                if not org:
                    org = hint_org
                if not asn:
                    asn = hint_asn
                if not cc:
                    cc = h_cc
                if lat is None or lon is None:
                    lat, lon = _jitter_coords(ip_str, h_lat, h_lon)
                break

        if not cc and domain_country:
            cc = domain_country
        if not org and domain_org:
            org = domain_org

        if (lat is None or lon is None) and cc and cc in COUNTRY_CENTROIDS:
            c_lat, c_lon, _ = COUNTRY_CENTROIDS[cc]
            lat, lon = _jitter_coords(ip_str, c_lat, c_lon)

        if lat is None or lon is None:
            # Deterministic fallback to US/Global internet exchange hub when country is unknown
            cc = cc or "US"
            c_lat, c_lon, _ = COUNTRY_CENTROIDS.get(cc, (37.77, -97.00, "United States"))
            lat, lon = _jitter_coords(ip_str, c_lat, c_lon)

        country_name = COUNTRY_CENTROIDS.get(cc or "", (0.0, 0.0, cc or "Global"))[2]
        svg_x, svg_y = _project_svg(lat, lon)
        ports_sorted = sorted(rec["ports"], key=lambda p: int(p) if p.isdigit() else 99999)
        vulns_sorted = sorted(rec["vulns"])
        hostnames_sorted = sorted(rec["hostnames"])
        all_ports.update(ports_sorted)
        if vulns_sorted:
            vuln_nodes += 1
        if cc:
            country_counts[cc] = country_counts.get(cc, 0) + 1
        provider_label = org or asn or "Unattributed Network"
        provider_counts[provider_label] = provider_counts.get(provider_label, 0) + 1

        points.append({
            "id": f"geo:{ip_str}",
            "ip": ip_str,
            "label": hostnames_sorted[0] if hostnames_sorted else ip_str,
            "hostnames": hostnames_sorted[:12],
            "country": cc or "US",
            "country_name": country_name,
            "city": city or country_name,
            "lat": round(lat, 4),
            "lon": round(lon, 4),
            "x": svg_x,
            "y": svg_y,
            "org": org or "Unknown Organization",
            "asn": asn or "ASN Unspecified",
            "cidr": rec["cidr"] or "",
            "ports": ports_sorted[:24],
            "vulns": vulns_sorted[:20],
            "cpes": sorted(rec["cpes"])[:15],
            "tags": sorted(rec["tags"])[:10],
            "severity": "critical" if vulns_sorted else ("elevated" if any(p in ("22", "23", "3389", "445", "3306", "5432", "6379", "27017") for p in ports_sorted) else "normal"),
            "fact_ids": rec["fact_ids"][:20],
        })

    # Build geodesic arcs from the primary point (or center hub) to secondary points
    arcs: list[dict[str, Any]] = []
    if len(points) >= 2:
        hub = points[0]
        for target_pt in points[1:]:
            arcs.append({
                "from_ip": hub["ip"],
                "to_ip": target_pt["ip"],
                "x1": hub["x"],
                "y1": hub["y"],
                "x2": target_pt["x"],
                "y2": target_pt["y"],
            })

    countries_summary = [
        {
            "code": code,
            "name": COUNTRY_CENTROIDS.get(code, (0.0, 0.0, code))[2],
            "count": count,
        }
        for code, count in sorted(country_counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    providers_summary = [
        {"name": name, "count": count}
        for name, count in sorted(provider_counts.items(), key=lambda item: (-item[1], item[0]))
    ]

    return {
        "target": company,
        "subject_kind": subject_kind,
        "points": points,
        "arcs": arcs,
        "summary": {
            "total_nodes": len(points),
            "countries_count": len(countries_summary),
            "providers_count": len(providers_summary),
            "open_ports_count": len(all_ports),
            "vulnerable_nodes_count": vuln_nodes,
            "countries": countries_summary,
            "providers": providers_summary,
        },
    }


def _csv_safe(val: Any) -> str:
    text = str(val or "").replace("\r", " ").replace("\n", " ").strip()
    if text.startswith(("=", "+", "-", "@", "\t", "|")):
        return "'" + text
    return text


def _node_maltego_type(node: dict[str, Any], root_domain: str = "") -> str:
    kind = str(node.get("kind") or "domain")
    label = str(node.get("label") or "").lower()
    if kind == "domain" and root_domain and label != root_domain.lower() and label.endswith("." + root_domain.lower()):
        return "maltego.DNSName"
    return MALTEGO_ENTITY_MAP.get(kind, "maltego.Phrase")


def build_maltego_graphml(brief: dict[str, Any]) -> str:
    """Export an investigation brief's graph & infrastructure as Maltego-compatible GraphML (.graphml)."""
    graph = brief.get("graph") or {}
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    root_domain = str(brief.get("company") or "")

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns"',
        '         xmlns:maltego="http://www.paterva.com/2011/xml/maltego">',
        '  <key id="d_type" for="node" attr.name="MaltegoEntityType" attr.type="string"/>',
        '  <key id="d_label" for="node" attr.name="Value" attr.type="string"/>',
        '  <key id="d_kind" for="node" attr.name="Find3rKind" attr.type="string"/>',
        '  <key id="e_label" for="edge" attr.name="Relation" attr.type="string"/>',
        '  <key id="e_source" for="edge" attr.name="AdapterSource" attr.type="string"/>',
        '  <graph id="Find3rMaltegoGraph" edgedefault="directed">',
    ]
    for node in nodes:
        nid = _xml_escape(str(node.get("id") or ""))
        label = _xml_escape(str(node.get("label") or ""))
        kind = str(node.get("kind") or "domain")
        m_type = _xml_escape(_node_maltego_type(node, root_domain))
        lines.append(f'    <node id="{nid}">')
        lines.append(f'      <data key="d_type">{m_type}</data>')
        lines.append(f'      <data key="d_label">{label}</data>')
        lines.append(f'      <data key="d_kind">{_xml_escape(kind)}</data>')
        lines.append("    </node>")

    for idx, edge in enumerate(edges):
        src = _xml_escape(str(edge.get("source") or ""))
        dst = _xml_escape(str(edge.get("target") or ""))
        rel = _xml_escape(str(edge.get("kind") or edge.get("relation") or "related_to"))
        prov = (edge.get("provenance") or [{}])[0] if isinstance(edge.get("provenance"), list) and edge.get("provenance") else {}
        adapter = _xml_escape(str(edge.get("retrieved_by") or prov.get("source") or "find3r"))
        lines.append(f'    <edge id="e{idx}" source="{src}" target="{dst}">')
        lines.append(f'      <data key="e_label">{rel}</data>')
        lines.append(f'      <data key="e_source">{adapter}</data>')
        lines.append("    </edge>")

    lines.append("  </graph>")
    lines.append("</graphml>")
    return "\n".join(lines) + "\n"


def build_maltego_csv(brief: dict[str, Any]) -> str:
    """Export an investigation brief as a Maltego Entity & Link table (.csv)."""
    graph = brief.get("graph") or {}
    nodes = {n.get("id"): n for n in (graph.get("nodes") or []) if isinstance(n, dict)}
    edges = graph.get("edges") or []
    root_domain = str(brief.get("company") or "")

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Source Entity Type",
        "Source Value",
        "Relation",
        "Target Entity Type",
        "Target Value",
        "Adapter",
        "Confidence",
    ])
    for edge in edges:
        src_node = nodes.get(edge.get("source")) or {"kind": "domain", "label": edge.get("source")}
        dst_node = nodes.get(edge.get("target")) or {"kind": "domain", "label": edge.get("target")}
        src_type = _node_maltego_type(src_node, root_domain)
        dst_type = _node_maltego_type(dst_node, root_domain)
        prov = (edge.get("provenance") or [{}])[0] if isinstance(edge.get("provenance"), list) and edge.get("provenance") else {}
        writer.writerow([
            _csv_safe(src_type),
            _csv_safe(src_node.get("label")),
            _csv_safe(edge.get("kind") or edge.get("relation") or "linked"),
            _csv_safe(dst_type),
            _csv_safe(dst_node.get("label")),
            _csv_safe(edge.get("retrieved_by") or prov.get("source") or "find3r"),
            _csv_safe(edge.get("confidence") or prov.get("confidence") or "medium"),
        ])
    return buf.getvalue()


def build_maltego_transform_xml(facts: list[dict[str, Any]]) -> str:
    """Render guarded facts as a Maltego Local Transform XML response."""
    attr_to_maltego = {
        "dns.subdomain": "maltego.DNSName",
        "discovery.subdomain": "maltego.DNSName",
        "dns.a": "maltego.IPv4Address",
        "dns.aaaa": "maltego.IPv6Address",
        "dns.passive.ipv4": "maltego.IPv4Address",
        "dns.passive.ipv6": "maltego.IPv6Address",
        "dns.mx": "maltego.DNSName",
        "dns.ns": "maltego.DNSName",
        "dns.cname": "maltego.DNSName",
        "host.reverse_dns": "maltego.DNSName",
        "whois.nameserver": "maltego.DNSName",
        "tls.san": "maltego.DNSName",
        "company.business_email": "maltego.EmailAddress",
        "person.business_email": "maltego.EmailAddress",
        "company.business_phone": "maltego.PhoneNumber",
        "person.business_phone": "maltego.PhoneNumber",
        "person.name": "maltego.Person",
        "host.port": "maltego.Port",
        "host.vuln": "maltego.Vulnerability",
        "host.asn": "maltego.AS",
        "host.org": "maltego.Company",
        "host.isp": "maltego.Company",
        "whois.org": "maltego.Company",
        "company.social_url": "maltego.URL",
        "person.linkedin_url": "maltego.URL",
        "person.twitter_handle": "maltego.Alias",
        "public.account.found": "maltego.Alias",
        "public.account.url": "maltego.URL",
    }
    lines = [
        "<MaltegoMessage>",
        "  <MaltegoTransformResponseMessage>",
        "    <Entities>",
    ]
    seen: set[tuple[str, str]] = set()
    for f in facts:
        attr = str(f.get("attribute") or "")
        val = str(f.get("value") or "").strip()
        if not val:
            continue
        m_type = attr_to_maltego.get(attr)
        if not m_type or (m_type, val) in seen:
            continue
        seen.add((m_type, val))
        lines.append(f'      <Entity Type="{_xml_escape(m_type)}">')
        lines.append(f"        <Value>{_xml_escape(val)}</Value>")
        lines.append("        <Weight>100</Weight>")
        lines.append("        <AdditionalFields>")
        lines.append(f'          <Field Name="find3r.attribute" DisplayName="Attribute">{_xml_escape(attr)}</Field>')
        lines.append(f'          <Field Name="find3r.source" DisplayName="Source">{_xml_escape(str(f.get("source") or "find3r"))}</Field>')
        lines.append(f'          <Field Name="find3r.admiralty" DisplayName="Admiralty">{_xml_escape(str(f.get("admiralty") or "C3"))}</Field>')
        lines.append("        </AdditionalFields>")
        lines.append("      </Entity>")
    lines += [
        "    </Entities>",
        "    <UIMessages/>",
        "  </MaltegoTransformResponseMessage>",
        "</MaltegoMessage>",
    ]
    return "\n".join(lines) + "\n"

import json

from neesha.audit import AuditLog


def test_audit_log_appends_jsonl(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.log({"action": "evidence", "target": "example.com"})
    log.log({"action": "collection-denied", "target": "example.com"})

    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["action"] == "evidence"
    assert first["target"] == "example.com"
    assert "timestamp" in first


def test_audit_log_is_append_only(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.log({"action": "a"})
    # a second log on the same path appends, it does not overwrite
    AuditLog(tmp_path / "audit.jsonl").log({"action": "b"})
    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert [json.loads(l)["action"] for l in lines] == ["a", "b"]

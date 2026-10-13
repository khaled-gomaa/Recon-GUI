from recon.finding_correlator import correlate_findings


def test_correlator_uses_evidence_and_does_not_claim_form_fields_prove_a_vulnerability():
    report = {
        "forms": [{
            "page": "http://example.com/login", "action": "https://collector.invalid/submit",
            "same_origin_action": False, "method": "POST",
            "fields": [{"name": "password", "type": "password"}],
            "csrf_field_present": False,
        }],
        "sensitive_findings": [{
            "page": "https://example.com/app.js", "type": "JWT-like token",
            "severity": "medium", "source": "document", "match": "[REDACTED]",
        }],
        "parameters": [{
            "name": "access_token", "classification": "sensitive-name",
            "sources": ["javascript"], "occurrences": 1, "locations": ["/app.js"],
        }],
        "history_diff": {"previous_scan_id": 1, "added_endpoints": ["/api/new"], "added_parameters": ["tenant"]},
    }
    findings = correlate_findings(report)
    titles = [item["title"] for item in findings]
    assert any("Potential exposed value pattern" in item for item in titles)
    assert any("different origin" in item for item in titles)
    assert any("Sensitive-looking parameter name" in item for item in titles)
    assert any("newly observed" in item for item in titles)
    external = next(item for item in findings if "different origin" in item["title"])
    assert external["evidence"]
    assert external["recommendation"]
    assert "definitely vulnerable" not in repr(findings).lower()


def test_first_scan_does_not_label_baseline_entities_as_new():
    findings = correlate_findings({
        "parameters": [],
        "history_diff": {
            "previous_scan_id": None,
            "added_endpoints": ["/api/users"],
            "added_parameters": ["id"],
        },
    })
    assert findings == []

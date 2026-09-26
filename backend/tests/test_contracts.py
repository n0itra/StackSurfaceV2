from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend" / "index.html"


def test_target_normalization_contract():
    import sys
    sys.path.insert(0, str(BACKEND))
    from app.utils import normalize_input, in_scope

    values = [
        "example.com",
        "https://example.com",
        "www.example.com",
        "https://www.example.com/login?next=/",
    ]
    normalized = [normalize_input(v) for v in values]
    assert {x[0] for x in normalized} == {"example.com"}
    assert in_scope("api.example.com", "example.com")
    assert not in_scope("example.net", "example.com")


def test_single_worker_contract():
    compose = (ROOT / "docker-compose.yml").read_text()
    assert "worker:" in compose
    assert "worker1:" not in compose
    assert "worker2:" not in compose
    env = (ROOT / ".env.example").read_text()
    assert "MAX_CONCURRENT_SCANS=1" in env


def test_stop_scan_contract():
    main = (BACKEND / "app" / "main.py").read_text()
    pipeline = (BACKEND / "app" / "pipeline.py").read_text()
    assert '@app.post("/api/scans/{scan_id}/stop")' in main
    assert "scan.cancel_requested = True" in main
    assert "URL must contain FUZZ" in main
    assert "class ScanCancelled" in pipeline
    assert "start_new_session=True" in pipeline
    assert "_terminate_process_group" in pipeline
    assert 'scan.status = "cancelled"' in pipeline


def test_httpx_filter_contract():
    pipeline = (BACKEND / "app" / "pipeline.py").read_text()
    assert '-mc", "200,401,403,404"' in pipeline
    assert "status_ok" in pipeline
    assert "return status in {200, 401, 403, 404}" in pipeline


def test_infrastructure_shodan_cdn_contract():
    pipeline = (BACKEND / "app" / "pipeline.py").read_text()
    assert "InfrastructureIP" in pipeline
    assert 'InfrastructureIP.cdn.is_(False)' in pipeline
    assert '"cdncheck"' in pipeline
    assert '"shodan"' in pipeline


def test_frontend_is_api_driven_and_scan_scoped_ffuf():
    html = FRONTEND.read_text()
    assert "FFUF Workspace" not in html
    assert "data-page=\"ffuf\"" not in html
    assert "openScanFfuf" in html
    assert "/api/ffuf-runs" in html
    assert "/api/scans/${id}/stop" in html
    assert "/api/scans" in html
    assert "New Scan" in html
    assert "Stop Scan" in html
    assert "mode:$('ffufMode').value" in html or "mode:$('ffufMode').value" in html


def test_frontend_scan_history_is_merged():
    html = FRONTEND.read_text()
    assert 'data-page="scan-history"' not in html
    assert 'page-scan-history' not in html
    assert 'Scan History' in html


def test_all_python_sources_compile():
    import py_compile
    files = list((BACKEND / "app").glob("*.py")) + [BACKEND / "worker.py"]
    for file in files:
        py_compile.compile(str(file), doraise=True)

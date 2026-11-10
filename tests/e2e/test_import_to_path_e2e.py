import os
import subprocess
import sys
import time
import urllib.request
import uuid
from collections.abc import Generator
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright

ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
FRONTEND_DIR = ROOT_DIR / "frontend"
SAMPLE_DIR = ROOT_DIR / "sample-data"

API_PORT = 8011
UI_PORT = 4174
API_BASE = f"http://127.0.0.1:{API_PORT}"
UI_BASE = f"http://127.0.0.1:{UI_PORT}"


def _wait_http_ok(url: str, timeout_s: float = 25.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2.0) as resp:  # noqa: S310
                if 200 <= resp.status < 400:
                    return
        except Exception as exc:  # noqa: BLE001
            last_err = exc
        time.sleep(0.25)
    raise RuntimeError(f"Service at {url} failed to start within {timeout_s}s: {last_err}")


def _resolve_chromium_executable() -> str | None:
    for candidate in ("/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"):
        if os.path.exists(candidate):
            return candidate
    return None


@pytest.fixture(scope="module")
def live_servers() -> Generator[tuple[str, str], None, None]:
    backend_env = {
        **os.environ,
        "ALLOWED_ORIGINS": f"{UI_BASE},http://localhost:{UI_PORT}",
        "PYTHONPATH": str(BACKEND_DIR),
    }
    frontend_env = {
        **os.environ,
        "VITE_API_PROXY_TARGET": API_BASE,
    }

    api_proc = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(API_PORT),
        ],
        cwd=str(BACKEND_DIR),
        env=backend_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    ui_proc = subprocess.Popen(  # noqa: S603
        [  # noqa: S607
            "npx",
            "vite",
            "preview",
            "--host",
            "127.0.0.1",
            "--port",
            str(UI_PORT),
            "--strictPort",
        ],
        cwd=str(FRONTEND_DIR),
        env=frontend_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    try:
        _wait_http_ok(f"{API_BASE}/api/v1/healthz")
        _wait_http_ok(f"{UI_BASE}/login")
        yield API_BASE, UI_BASE
    finally:
        for proc in (ui_proc, api_proc):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()


@pytest.mark.e2e
def test_browser_full_workflow_and_accessibility_smoke(
    live_servers: tuple[str, str],
) -> None:
    _, ui_url = live_servers
    exe_path = _resolve_chromium_executable()

    with sync_playwright() as p:
        launch_kwargs: dict[str, object] = {
            "headless": True,
            "args": ["--no-sandbox", "--disable-dev-shm-usage"],
        }
        if exe_path:
            launch_kwargs["executable_path"] = exe_path

        browser = p.chromium.launch(**launch_kwargs)  # type: ignore[arg-type]
        context = browser.new_context(viewport={"width": 1366, "height": 900})
        page = context.new_page()

        page_errors: list[str] = []
        console_errors: list[str] = []
        http_errors: list[str] = []
        page.on("pageerror", lambda err: page_errors.append(str(err)))
        page.on(
            "console",
            lambda msg: console_errors.append(
                f"{msg.text} ({msg.location.get('url', '')})"
            )
            if msg.type == "error"
            else None,
        )
        page.on(
            "response",
            lambda res: http_errors.append(f"{res.status} {res.url}") if res.status >= 400 else None,
        )

        try:
            # 1. Login flow
            page.goto(f"{ui_url}/login", wait_until="networkidle")
            assert page.get_by_role("heading", name="SentinelGraph Sign In").is_visible()
            page.fill("#login-email", "admin@acme.local")
            page.fill("#login-password", "SentinelDemo!2026")
            page.fill("#login-tenant", "acme-demo")
            page.get_by_role("button", name="Sign In", exact=True).click()

            page.wait_for_url("**/overview")
            page.get_by_role("heading", name="Overview Dashboard").wait_for(state="visible", timeout=10000)
            page.locator("text=DEMO / SYNTHETIC LAB TENANT").wait_for(state="visible", timeout=10000)
            page.locator(".kpi-card").first.wait_for(state="visible", timeout=10000)
            assert page.locator(".kpi-card").count() == 7

            # 2. Assessments & Cytoscape Graph Explorer + Centerpiece Intelligence
            page.get_by_role("link", name="Assessments & Graph").click()
            page.wait_for_url("**/assessments")
            page.locator("canvas").first.wait_for(state="visible", timeout=10000)
            canvas_box = page.locator("canvas").first.bounding_box()
            assert canvas_box is not None
            assert canvas_box["width"] > 200
            assert canvas_box["height"] > 200
            page.locator("text=Betweenness Centrality").wait_for(state="visible", timeout=10000)
            page.locator("text=Minimum Cut-Set Size").wait_for(state="visible", timeout=10000)

            page.get_by_role("tab", name="Minimum Cut-Sets").click()
            preview_cut_btn = page.get_by_role("button", name="Preview").first
            preview_cut_btn.wait_for(state="visible", timeout=10000)
            preview_cut_btn.click()
            page.locator("text=Cut-Set Overlay [CUT]:").wait_for(state="visible", timeout=10000)

            page.get_by_role("tab", name="Assumption Sensitivity").click()
            page.locator("text=Exclude Inferred Heuristic Edges").wait_for(
                state="visible", timeout=10000
            )

            # 3. Attack Paths -> Path Detail Causal Graph Debugger
            page.get_by_role("link", name="Attack Paths").click()
            page.wait_for_url("**/paths")
            page.get_by_role("link", name="Inspect Reasoning").first.wait_for(
                state="visible", timeout=10000
            )
            page.get_by_role("link", name="Inspect Reasoning").first.click()
            page.wait_for_url("**/paths/**")
            path_detail_url = page.url
            page.locator("text=NOT a statistical probability").wait_for(
                state="visible", timeout=10000
            )
            page.locator("canvas").first.wait_for(state="visible", timeout=10000)
            sub_box = page.locator("canvas").first.bounding_box()
            assert sub_box is not None and sub_box["width"] > 200 and sub_box["height"] > 200
            page.locator("text=Causal Mechanism").wait_for(state="visible", timeout=10000)

            page.get_by_role("tab", name="Assumptions & Sensitivity").click()
            page.locator("text=Typed Assumptions Register").wait_for(
                state="visible", timeout=10000
            )
            page.locator("text=Per-Step Removal Counterfactuals").wait_for(
                state="visible", timeout=10000
            )

            page.get_by_role("tab", name="Which Fix Breaks It").click()
            sim_fix_btn = page.get_by_role("button", name="Simulate").first
            sim_fix_btn.wait_for(state="visible", timeout=10000)
            sim_fix_btn.click()
            page.locator("text=Modelled Post-Remediation").first.wait_for(
                state="visible", timeout=10000
            )

            page.locator("text=Step 1:").first.wait_for(state="visible", timeout=10000)
            page.get_by_role("button", name="Show Structured JSON Trace").click()
            page.locator("text=plausible_only").wait_for(state="visible", timeout=10000)

            # 4. Remediation Sandbox Simulator
            page.get_by_role("link", name="Remediation Planner").click()
            page.wait_for_url("**/remediations")
            page.wait_for_function(
                "() => (document.querySelector('#rem-assess')?.options.length || 0) > 0",
                timeout=10000,
            )
            scenario_name = f"E2E Segment Scenario {uuid.uuid4().hex[:6]}"
            page.fill("#rem-name", scenario_name)
            page.get_by_role("button", name="Run Before / After Simulation").click()
            page.locator(f"text={scenario_name}").first.wait_for(state="visible", timeout=10000)
            page.locator("text=Modelled Post-Remediation").first.wait_for(
                state="visible", timeout=10000
            )

            # 5. Staged Imports Upload -> Preview -> Approve -> Commit
            page.get_by_role("link", name="Imports (Staged)").click()
            page.wait_for_url("**/imports")
            page.wait_for_function(
                "() => (document.querySelector('#imp-assess')?.options.length || 0) > 0",
                timeout=10000,
            )
            idem = f"e2e-imp-{uuid.uuid4().hex[:8]}"
            page.fill("#imp-idem", idem)
            page.set_input_files("#imp-file", str(SAMPLE_DIR / "followup_nmap_scan.xml"))
            page.get_by_role("button", name="Upload & Preview Stage").click()
            page.locator('text=Staged "followup_nmap_scan.xml"').wait_for(
                state="visible", timeout=10000
            )

            approve_btn = page.get_by_role("button", name="Approve").first
            approve_btn.wait_for(state="visible", timeout=10000)
            approve_btn.click()
            commit_btn = page.get_by_role("button", name="Commit Atomically").first
            commit_btn.wait_for(state="visible", timeout=10000)
            commit_btn.click()
            page.locator("text=Import committed into normalised tenant inventory").wait_for(
                state="visible", timeout=10000
            )

            # 6. Reports (generate & preview in sandboxed iframe) & Audit Log
            page.get_by_role("link", name="Reports").click()
            page.wait_for_url("**/reports")
            page.wait_for_function(
                "() => (document.querySelector('#rep-assess')?.options.length || 0) > 0",
                timeout=10000,
            )
            page.fill("#rep-title", f"E2E Report {uuid.uuid4().hex[:6]}")
            page.get_by_role("button", name="Generate HTML Report").click()
            iframe = page.locator("iframe.report-frame")
            iframe.wait_for(state="visible", timeout=10000)
            assert iframe.get_attribute("sandbox") == ""

            page.get_by_role("link", name="Audit Log").click()
            page.wait_for_url("**/audit")
            page.locator("text=Event Hash Chain").wait_for(state="visible", timeout=10000)
            page.locator("text=hash:").first.wait_for(state="visible", timeout=10000)

            # 7. Findings & Triage workflow (without altering exploitability_proven=false invariant)
            page.get_by_role("link", name="Findings & Triage").click()
            page.wait_for_url("**/findings")
            page.get_by_role("heading", name="Vulnerability Findings & Analyst Triage").wait_for(
                state="visible", timeout=10000
            )
            page.locator("text=exploitability_proven = false").wait_for(state="visible", timeout=10000)
            triage_btn = page.get_by_role("button", name="Triage").first
            triage_btn.wait_for(state="visible", timeout=10000)
            triage_btn.click()
            triage_dialog = page.locator("dialog[open]")
            triage_dialog.wait_for(state="visible", timeout=5000)
            page.fill("#triage-note", "E2E analyst triage verification")
            page.get_by_role("button", name="Save Triage Decision").click()
            page.locator("text=Triaged ").wait_for(state="visible", timeout=10000)

            # 8. Background Jobs queue & semantic <progress> bar
            page.get_by_role("link", name="Background Jobs").click()
            page.wait_for_url("**/jobs")
            page.get_by_role("heading", name="Background Worker Jobs & Queue Status").wait_for(
                state="visible", timeout=10000
            )
            page.wait_for_function(
                "() => (document.querySelector('#job-assess')?.options.length || 0) > 0",
                timeout=10000,
            )
            page.get_by_role("button", name="Enqueue Worker Job").click()
            page.locator('text=Background job "build_graph"').wait_for(
                state="visible", timeout=10000
            )
            page.locator("progress").first.wait_for(state="visible", timeout=10000)

            # Verify new enterprise adapter options on Imports and multi-format buttons on Reports
            page.get_by_role("link", name="Imports (Staged)").click()
            page.wait_for_url("**/imports")
            assert page.locator('#imp-fmt option[value="nessus_xml"]').count() == 1
            assert page.locator('#imp-fmt option[value="sarif_json"]').count() == 1
            assert page.locator('#imp-fmt option[value="bloodhound_json"]').count() == 1
            assert page.locator('#imp-fmt option[value="aws_iam_export_json"]').count() == 1

            page.get_by_role("link", name="Reports").click()
            page.wait_for_url("**/reports")
            page.get_by_role("button", name="SARIF", exact=True).first.wait_for(
                state="visible", timeout=10000
            )

            # 9. Settings, Member Provisioning, Webhooks & Integrations + Global Search Modal Dialog
            page.get_by_role("link", name="Settings & Privacy").click()
            page.wait_for_url("**/settings")
            page.locator("text=Invite / Provision Member").wait_for(state="visible", timeout=10000)
            page.locator("text=Outbound Webhooks").wait_for(state="visible", timeout=10000)

            page.get_by_role("link", name="Connectors").click()
            page.wait_for_url("**/integrations")
            page.locator("text=Phase 2 Read-Only Cloud").wait_for(state="visible", timeout=10000)

            search_input = page.get_by_placeholder("Search tenant inventory...")
            search_input.fill("web-dmz-01")
            page.get_by_role("button", name="Search", exact=True).click()
            dialog = page.locator("dialog[open]")
            dialog.wait_for(state="visible", timeout=5000)
            assert "web-dmz-01" in dialog.inner_text()
            page.keyboard.press("Escape")
            dialog.wait_for(state="hidden", timeout=5000)

            # 10. Responsive Mobile Layout Check (no horizontal page overflow on key routes)
            page.set_viewport_size({"width": 390, "height": 844})
            for mobile_url, marker in [
                (f"{ui_url}/overview", ".kpi-card"),
                (f"{ui_url}/assessments", "text=Minimum Cut-Set Size"),
                (path_detail_url, "text=Graph Engine Causal Debugger"),
            ]:
                page.goto(mobile_url, wait_until="networkidle")
                page.locator(marker).first.wait_for(state="visible", timeout=10000)
                overflow = page.evaluate(
                    "() => document.documentElement.scrollWidth - window.innerWidth"
                )
                assert overflow <= 2, f"Unexpected horizontal overflow on {mobile_url}: {overflow}px"

            assert page_errors == [], f"Uncaught page errors: {page_errors}"
            assert console_errors == [], (
                f"Console errors: {console_errors} | HTTP >=400 responses: {http_errors}"
            )
            assert http_errors == [], f"Unexpected HTTP >=400 responses: {http_errors}"
        finally:
            context.close()
            browser.close()

#!/usr/bin/env python3
"""
fix_vapi_endpoint.py

Comprehensive VMware vCenter VAPI Endpoint & Appliance Service Remediation Tool.

Diagnoses and resolves issues where the VMware vCenter VAPI Endpoint service
(vmware-vapi-endpoint / vapi-endpoint) or other essential appliance services
are STOPPED on vCenter Server appliances (e.g. vc-mgmt-b.site-b.vcf.lab).

When vmware-vapi-endpoint is down:
  - Port 443 /api/session and /rest/... endpoints return HTTP 503 "no healthy upstream"
  - vSphere Client UI (/ui) fails or experiences degraded authentication
  - SDDC Manager, Aria Operations, and NSX integrations encounter VAPI failures

Features
--------
1. Service Status Discovery:
   - Queries service status via vCenter Appliance Shell (service-control --status)
     and VAMI REST API (Port 5480 /rest/appliance/services).
2. Service Remediation & Startup:
   - Starts or restarts stopped services using appliance service control.
   - Supports specific services (default: vmware-vapi-endpoint) or --all-stopped.
3. Multi-vCenter Support:
   - Targets a specific vCenter (default: vc-mgmt-b.site-b.vcf.lab) or scans
     all vCenters across the lab topology (--all-vcenters).
4. End-to-End Health Verification:
   - Validates post-startup service state via service-control.
   - Validates vCenter REST / VAPI API on Port 443 (POST /api/session and
     POST /rest/com/vmware/cis/session).
   - Validates VAMI system health on Port 5480.
5. Zero External Dependencies:
   - Pure Python 3 standard library (stdlib only).

Usage
-----
    python3 fix_vapi_endpoint.py                          # Fix vc-mgmt-b (default)
    python3 fix_vapi_endpoint.py --vc-host vc-mgmt-a.site-a.vcf.lab
    python3 fix_vapi_endpoint.py --all-vcenters           # Scan & fix all lab vCenters
    python3 fix_vapi_endpoint.py --restart                # Force restart service
    python3 fix_vapi_endpoint.py --dry-run                # Inspect without modifying
    python3 fix_vapi_endpoint.py --verbose                # Detailed API & debug output
"""

import argparse
import base64
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ── Configuration Defaults ────────────────────────────────────────────────────

DEFAULT_VC_HOST       = "vc-mgmt-b.site-b.vcf.lab"
DEFAULT_VC_USER       = "administrator@vsphere.local"
DEFAULT_SERVICE       = "vmware-vapi-endpoint"
DEFAULT_PASSWORD_FILE = "/home/holuser/creds.txt"

ALL_VCF_VCENTERS = [
    "vc-mgmt-a.site-a.vcf.lab",
    "vc-mgmt-b.site-b.vcf.lab",
    "vc-wld01-a.site-a.vcf.lab",
    "vc-wld01-b.site-b.vcf.lab",
]

RECHECK_WAIT = 15   # seconds to wait before re-checking service state post-startup

# ── Logging & Terminal Colors ─────────────────────────────────────────────────

COLORS = {
    "INFO":    "\033[36m",   # Cyan
    "SUCCESS": "\033[32m",   # Green
    "WARN":    "\033[33m",   # Yellow
    "ERROR":   "\033[31m",   # Red
    "API":     "\033[35m",   # Magenta
    "HEADER":  "\033[1;34m", # Bold Blue
    "BOLD":    "\033[1m",
    "RESET":   "\033[0m",
}

_verbose = False


def log(msg: str, level: str = "INFO") -> None:
    ts    = time.strftime("%Y-%m-%d %H:%M:%S")
    color = COLORS.get(level, "")
    reset = COLORS["RESET"]
    print(f"{color}[{ts}] [{level}] {msg}{reset}", flush=True)


def log_api(method: str, url: str, status: int, body: str = "") -> None:
    color = COLORS["API"]
    reset = COLORS["RESET"]
    ok    = status < 300
    status_color = COLORS["SUCCESS"] if ok else COLORS["ERROR"]
    print(
        f"{color}[API] {method} {url}{reset}  "
        f"{status_color}→ HTTP {status}{reset}",
        flush=True,
    )
    if body and _verbose:
        try:
            parsed = json.loads(body)
            print(json.dumps(parsed, indent=2), flush=True)
        except Exception:
            print(body[:500], flush=True)
    elif body and not ok and _verbose:
        print(f"  Response: {body[:300]}", flush=True)


def fail(msg: str, exit_code: int = 1) -> None:
    log(msg, "ERROR")
    sys.exit(exit_code)


# ── Result Tracking ───────────────────────────────────────────────────────────

@dataclass
class ServiceRemediationResult:
    vc_host:          str
    service_name:     str
    initial_state:    str           = "UNKNOWN"
    action:           str           = "NONE"
    final_state:      str           = "UNKNOWN"
    api_443_status:   str           = "UNKNOWN"
    vami_5480_status: str           = "UNKNOWN"
    error_message:    Optional[str] = None
    is_healthy:       bool          = False


# ── SSH & Appliance Shell Execution Client ───────────────────────────────────

class ApplianceSshClient:
    """
    Executes commands on vCenter Appliance Shell (appliancesh) via SSH.
    Supports sshpass if available or direct standard SSH.
    """

    def __init__(self, host: str, user: str, password: str, port: int = 22) -> None:
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self._has_sshpass = self._check_sshpass()

    @staticmethod
    def _check_sshpass() -> bool:
        try:
            res = subprocess.run(["which", "sshpass"], capture_output=True, text=True)
            return res.returncode == 0
        except Exception:
            return False

    def run_command(self, cmd_str: str, timeout: int = 60) -> Tuple[str, str, int]:
        """Runs a command on the vCenter appliance via SSH."""
        ssh_opts = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=10",
            "-p", str(self.port),
        ]

        if self._has_sshpass:
            cmd = ["sshpass", "-p", self.password, "ssh"] + ssh_opts + [
                f"{self.user}@{self.host}",
                cmd_str,
            ]
        else:
            cmd = ["ssh"] + ssh_opts + [
                f"{self.user}@{self.host}",
                cmd_str,
            ]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if _verbose:
                log(f"[SSH] {self.host}: {cmd_str} -> rc={res.returncode}", "INFO")
                if res.stdout.strip():
                    log(f"[SSH STDOUT] {res.stdout.strip()[:300]}", "INFO")
                if res.stderr.strip():
                    log(f"[SSH STDERR] {res.stderr.strip()[:300]}", "WARN")
            return res.stdout, res.stderr, res.returncode
        except subprocess.TimeoutExpired:
            return "", "SSH command timed out", 124
        except Exception as exc:
            return "", str(exc), 1


# ── vCenter & VAMI REST API Client ───────────────────────────────────────────

class VCenterApiClient:
    """
    Interacts with vCenter REST APIs:
      - Port 443: vSphere Automation / VAPI REST API (/api/session, /rest/...)
      - Port 5480: VAMI Appliance Management REST API (/rest/com/vmware/cis/session, /rest/appliance/...)
    """

    def __init__(self, host: str, user: str, password: str) -> None:
        self.host = host
        self.user = user
        self.password = password
        self._auth_header = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def test_port_443_vapi(self) -> Tuple[bool, str]:
        """
        Tests if vCenter Port 443 VAPI / REST endpoint is operational.
        POST /api/session
        """
        url = f"https://{self.host}:443/api/session"
        req = urllib.request.Request(
            url,
            method="POST",
            headers={"Authorization": self._auth_header, "Content-Length": "0"},
        )
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=10) as resp:
                log_api("POST", url, resp.status)
                return True, f"HTTP {resp.status} (Session OK)"
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            log_api("POST", url, exc.code, body)
            if exc.code == 503:
                return False, "HTTP 503 (vAPI Service Unavailable / Upstream Down)"
            return False, f"HTTP {exc.code} ({body[:100]})"
        except urllib.error.URLError as exc:
            return False, f"Connection Failed: {exc.reason}"
        except Exception as exc:
            return False, f"Error: {exc}"

    def test_port_443_cis_session(self) -> Tuple[bool, str]:
        """
        Tests if vCenter Port 443 CIS REST endpoint is operational.
        POST /rest/com/vmware/cis/session
        """
        url = f"https://{self.host}:443/rest/com/vmware/cis/session"
        req = urllib.request.Request(
            url,
            method="POST",
            headers={"Authorization": self._auth_header, "Content-Length": "0"},
        )
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=10) as resp:
                log_api("POST", url, resp.status)
                return True, f"HTTP {resp.status} (CIS Session OK)"
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            log_api("POST", url, exc.code, body)
            return False, f"HTTP {exc.code}"
        except Exception as exc:
            return False, f"Error: {exc}"

    def get_vami_session(self) -> Optional[str]:
        """
        Authenticates against VAMI Port 5480 CIS session endpoint.
        Returns the session ID string if successful.
        """
        url = f"https://{self.host}:5480/rest/com/vmware/cis/session"
        req = urllib.request.Request(
            url,
            method="POST",
            headers={"Authorization": self._auth_header, "Content-Length": "0"},
        )
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=10) as resp:
                log_api("POST", url, resp.status)
                data = json.loads(resp.read().decode())
                return data.get("value")
        except Exception as exc:
            if _verbose:
                log(f"VAMI CIS session auth failed on {self.host}:5480: {exc}", "WARN")
            return None

    def check_vami_health(self) -> Tuple[bool, str]:
        """Checks VAMI Port 5480 system health."""
        session_id = self.get_vami_session()
        if not session_id:
            return False, "VAMI Auth Failed"

        url = f"https://{self.host}:5480/rest/appliance/health/system"
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"vmware-api-session-id": session_id},
        )
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=10) as resp:
                log_api("GET", url, resp.status)
                data = json.loads(resp.read().decode())
                health = data.get("value", "unknown")
                return (health == "green"), f"Health: {health}"
        except Exception as exc:
            return False, f"Health Check Error: {exc}"

    def list_vami_services(self) -> Dict[str, Dict[str, str]]:
        """
        Queries all appliance services from VAMI Port 5480 REST API.
        Returns dict: {service_key: {"description": ..., "state": ...}}
        """
        session_id = self.get_vami_session()
        if not session_id:
            return {}

        url = f"https://{self.host}:5480/rest/appliance/services"
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"vmware-api-session-id": session_id},
        )
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=15) as resp:
                log_api("GET", url, resp.status)
                data = json.loads(resp.read().decode())
                services = {}
                for item in data.get("value", []):
                    key = item.get("key")
                    val = item.get("value", {})
                    if key:
                        services[key] = {
                            "description": val.get("description", ""),
                            "state": val.get("state", "UNKNOWN"),
                        }
                return services
        except Exception as exc:
            if _verbose:
                log(f"Failed to list VAMI services on {self.host}: {exc}", "WARN")
            return {}


# ── Remediation Engine ────────────────────────────────────────────────────────

class VCenterServiceRemediator:
    def __init__(
        self,
        vc_host: str,
        user: str,
        password: str,
        dry_run: bool = False,
    ) -> None:
        self.vc_host = vc_host
        self.user = user
        self.password = password
        self.dry_run = dry_run
        self.ssh_client = ApplianceSshClient(vc_host, user, password)
        self.api_client = VCenterApiClient(vc_host, user, password)

    def get_service_status_ssh(self) -> Tuple[List[str], List[str]]:
        """
        Queries service status via appliancesh `service-control --status`.
        Returns tuple: (running_services, stopped_services)
        """
        stdout, stderr, rc = self.ssh_client.run_command("service-control --status")
        if rc != 0 and not stdout:
            log(f"SSH service-control command failed on {self.vc_host}: {stderr[:100]}", "WARN")
            return [], []

        running: List[str] = []
        stopped: List[str] = []
        current_section = None

        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("Running:"):
                current_section = "RUNNING"
                content = line.replace("Running:", "").strip()
                if content:
                    running.extend(content.split())
            elif line.startswith("Stopped:"):
                current_section = "STOPPED"
                content = line.replace("Stopped:", "").strip()
                if content:
                    stopped.extend(content.split())
            elif current_section == "RUNNING":
                running.extend(line.split())
            elif current_section == "STOPPED":
                stopped.extend(line.split())

        return running, stopped

    def is_service_running(self, target_service: str) -> Tuple[str, bool]:
        """
        Determines if the target service is running.
        Returns (state_string, is_running_bool).
        """
        running, stopped = self.get_service_status_ssh()
        
        # Check normalized service names (e.g. vmware-vapi-endpoint or vapi-endpoint)
        candidates = [target_service]
        if target_service.startswith("vmware-"):
            candidates.append(target_service[7:])
        else:
            candidates.append(f"vmware-{target_service}")

        for cand in candidates:
            if cand in running:
                return "RUNNING", True
            if cand in stopped:
                return "STOPPED", False

        # Fallback to API check if SSH did not match
        api_ok, api_msg = self.api_client.test_port_443_vapi()
        if "vapi" in target_service and api_ok:
            return "RUNNING", True

        return "UNKNOWN", False

    def start_service(self, service_name: str) -> Tuple[bool, str]:
        """
        Starts a service via service-control.
        """
        log(f"  → Initiating start for service: {service_name}", "WARN")
        if self.dry_run:
            log(f"  [DRY RUN] Would execute: service-control --start {service_name}", "WARN")
            return True, "DRY_RUN"

        stdout, stderr, rc = self.ssh_client.run_command(
            f"service-control --start {service_name}",
            timeout=120,
        )
        combined = (stdout + "\n" + stderr).strip()
        if rc == 0 or "Successfully started service" in combined:
            log(f"  Successfully started {service_name}", "SUCCESS")
            return True, "STARTED"
        else:
            log(f"  Failed to start {service_name}: {combined[:200]}", "ERROR")
            return False, combined[:200]

    def restart_service(self, service_name: str) -> Tuple[bool, str]:
        """
        Restarts a service via service-control.
        """
        log(f"  → Initiating restart for service: {service_name}", "WARN")
        if self.dry_run:
            log(f"  [DRY RUN] Would execute: service-control --restart {service_name}", "WARN")
            return True, "DRY_RUN"

        stdout, stderr, rc = self.ssh_client.run_command(
            f"service-control --restart {service_name}",
            timeout=120,
        )
        combined = (stdout + "\n" + stderr).strip()
        if rc == 0 or "Successfully restarted service" in combined or "Successfully started service" in combined:
            log(f"  Successfully restarted {service_name}", "SUCCESS")
            return True, "RESTARTED"
        else:
            log(f"  Failed to restart {service_name}: {combined[:200]}", "ERROR")
            return False, combined[:200]

    def remediate_target(
        self,
        service_name: str = DEFAULT_SERVICE,
        force_restart: bool = False,
    ) -> ServiceRemediationResult:
        """
        Executes end-to-end diagnosis, remediation, and verification for the target vCenter.
        """
        result = ServiceRemediationResult(
            vc_host=self.vc_host,
            service_name=service_name,
        )

        print()
        log(f"═══════════════════════════════════════════════════════════════", "HEADER")
        log(f"Target vCenter : {self.vc_host}", "HEADER")
        log(f"Target Service : {service_name}", "HEADER")
        log(f"═══════════════════════════════════════════════════════════════", "HEADER")

        # ── Step 1: Pre-check Initial Status ──────────────────────────────────
        log(f"Step 1: Inspecting initial service and API status on {self.vc_host}...")
        init_state, is_running = self.is_service_running(service_name)
        result.initial_state = init_state

        api_ok, api_msg = self.api_client.test_port_443_vapi()
        vami_ok, vami_msg = self.api_client.check_vami_health()

        state_color = "SUCCESS" if is_running else ("WARN" if init_state == "STOPPED" else "ERROR")
        api_color   = "SUCCESS" if api_ok else "ERROR"
        vami_color  = "SUCCESS" if vami_ok else "WARN"

        log(f"  Initial Service State : {init_state}", state_color)
        log(f"  Port 443 VAPI Status  : {api_msg}", api_color)
        log(f"  Port 5480 VAMI Status : {vami_msg}", vami_color)

        # ── Step 2: Determine Action ──────────────────────────────────────────
        needs_action = (not is_running) or force_restart or (not api_ok and "vapi" in service_name)

        if not needs_action:
            log(f"  Service {service_name} is already RUNNING and VAPI API is healthy — no action needed.", "SUCCESS")
            result.action = "NONE"
            result.final_state = init_state
            result.api_443_status = api_msg
            result.vami_5480_status = vami_msg
            result.is_healthy = True
            return result

        if self.dry_run:
            action_desc = "RESTART" if force_restart else "START"
            log(f"  [DRY RUN] Would execute {action_desc} on {service_name}", "WARN")
            result.action = f"DRY_RUN_{action_desc}"
            result.final_state = init_state
            result.api_443_status = api_msg
            result.vami_5480_status = vami_msg
            return result

        # ── Step 3: Perform Remediation ───────────────────────────────────────
        log(f"Step 2: Executing remediation for {service_name}...")
        if force_restart:
            success, action_res = self.restart_service(service_name)
            result.action = "RESTARTED" if success else "RESTART_FAILED"
        else:
            success, action_res = self.start_service(service_name)
            result.action = "STARTED" if success else "START_FAILED"

        if not success:
            result.error_message = action_res
            result.final_state = "FAILED"
            return result

        # ── Step 4: Wait for Service Initialization ───────────────────────────
        log(f"Step 3: Waiting {RECHECK_WAIT}s for {service_name} and dependent endpoints to initialize...")
        time.sleep(RECHECK_WAIT)

        # ── Step 5: Post-Remediation Verification ─────────────────────────────
        log(f"Step 4: Verifying post-remediation service state and API health...")
        final_state, final_running = self.is_service_running(service_name)
        result.final_state = final_state

        post_api_ok, post_api_msg = self.api_client.test_port_443_vapi()
        post_cis_ok, post_cis_msg = self.api_client.test_port_443_cis_session()
        post_vami_ok, post_vami_msg = self.api_client.check_vami_health()

        result.api_443_status = post_api_msg
        result.vami_5480_status = post_vami_msg

        final_color = "SUCCESS" if final_running else "ERROR"
        post_api_color = "SUCCESS" if post_api_ok else "ERROR"

        log(f"  Final Service State   : {final_state}", final_color)
        log(f"  Port 443 VAPI Status  : {post_api_msg}", post_api_color)
        log(f"  Port 443 CIS Status   : {post_cis_msg}", "SUCCESS" if post_cis_ok else "WARN")
        log(f"  Port 5480 VAMI Status : {post_vami_msg}", "SUCCESS" if post_vami_ok else "WARN")

        if final_running and (post_api_ok or "vapi" not in service_name):
            log(f"  Remediation SUCCESSFUL — {service_name} is fully operational!", "SUCCESS")
            result.is_healthy = True
        else:
            log(f"  Remediation INCOMPLETE — service did not reach healthy status.", "ERROR")
            result.is_healthy = False

        return result


# ── Password & Credential Loader ──────────────────────────────────────────────

def load_password(pw_arg: Optional[str], pw_file_arg: Optional[str]) -> str:
    """Loads vCenter password from argument, environment, file, or default."""
    if pw_arg:
        return pw_arg

    env_pw = os.environ.get("VCF_PASSWORD") or os.environ.get("VCENTER_PASSWORD")
    if env_pw:
        return env_pw

    file_path = pw_file_arg or DEFAULT_PASSWORD_FILE
    if os.path.isfile(file_path):
        try:
            pw = open(file_path).read().strip()
            if pw:
                log(f"Password loaded from file: {file_path}")
                return pw
        except Exception as exc:
            log(f"Could not read password file {file_path}: {exc}", "WARN")

    # Fallback to standard lab default password
    log(f"Using default lab credential", "WARN")
    return DEFAULT_FALLBACK_PW


# ── CLI Argument Parser ───────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "VMware vCenter VAPI Endpoint & Service Remediation Tool.\n\n"
            "Diagnoses and starts stopped vCenter appliance services (default: vmware-vapi-endpoint).\n"
            "Restores Port 443 /api/session and /rest API functionality across VCF vCenters."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--vc-host", default=DEFAULT_VC_HOST, metavar="FQDN",
        help=f"Target vCenter Server FQDN or IP (default: {DEFAULT_VC_HOST})",
    )
    p.add_argument(
        "--all-vcenters", action="store_true",
        help="Scan and remediate all vCenters in the lab topology",
    )
    p.add_argument(
        "--user", default=DEFAULT_VC_USER, metavar="USERNAME",
        help=f"vCenter admin user (default: {DEFAULT_VC_USER})",
    )
    p.add_argument(
        "--password", metavar="PASSWORD",
        help="vCenter admin password (if not reading from file)",
    )
    p.add_argument(
        "--password-file", default=DEFAULT_PASSWORD_FILE, metavar="PATH",
        help=f"Path to lab password file (default: {DEFAULT_PASSWORD_FILE})",
    )
    p.add_argument(
        "--service", default=DEFAULT_SERVICE, metavar="SERVICE_NAME",
        help=f"Specific appliance service name to check/start (default: {DEFAULT_SERVICE})",
    )
    p.add_argument(
        "--restart", action="store_true",
        help="Force service restart even if currently running",
    )
    p.add_argument(
        "--wait", type=int, default=RECHECK_WAIT, metavar="SECONDS",
        help=f"Wait time in seconds after starting service (default: {RECHECK_WAIT})",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Inspect service status and API health without executing start/restart actions",
    )
    p.add_argument(
        "--verbose", action="store_true",
        help="Enable verbose output including detailed API responses and SSH debug logs",
    )
    return p.parse_args()


# ── Summary Table Formatter ───────────────────────────────────────────────────

def print_summary_table(results: List[ServiceRemediationResult], dry_run: bool) -> bool:
    print()
    log("════════════════════ REMEDIATION SUMMARY ════════════════════", "HEADER")
    
    C_HOST = 28; C_SVC = 23; C_INIT = 10; C_ACT = 12; C_FIN = 10; C_API = 22
    hdr = (
        f"{'vCenter Host':<{C_HOST}} "
        f"{'Service':<{C_SVC}} "
        f"{'Initial':<{C_INIT}} "
        f"{'Action':<{C_ACT}} "
        f"{'Final':<{C_FIN}} "
        f"{'Port 443 VAPI':<{C_API}}"
    )
    print(hdr)
    print("-" * len(hdr))

    all_healthy = True
    for r in results:
        if r.is_healthy:
            color = COLORS["SUCCESS"]
        elif r.action.startswith("DRY_RUN"):
            color = COLORS["WARN"]
        else:
            color = COLORS["ERROR"]
            all_healthy = False

        vapi_summary = r.api_443_status.split("(")[0].strip() if "(" in r.api_443_status else r.api_443_status[:20]

        print(
            f"{color}"
            f"{r.vc_host:<{C_HOST}} "
            f"{r.service_name:<{C_SVC}} "
            f"{r.initial_state:<{C_INIT}} "
            f"{r.action:<{C_ACT}} "
            f"{r.final_state:<{C_FIN}} "
            f"{vapi_summary:<{C_API}}"
            f"{COLORS['RESET']}"
        )
        if r.error_message:
            print(f"  {'':>{C_HOST}} Error: {r.error_message[:80]}")

    print()
    if dry_run:
        log("Dry run complete — no modifications were made.", "WARN")
    elif all_healthy:
        log("All targeted vCenter services are healthy and operational!", "SUCCESS")
    else:
        log("One or more services failed remediation — review table above.", "ERROR")

    return all_healthy


# ── Main Entrypoint ───────────────────────────────────────────────────────────

def main() -> None:
    global _verbose, RECHECK_WAIT
    args = parse_args()
    _verbose = args.verbose
    RECHECK_WAIT = args.wait

    log("Starting VMware vCenter Service Remediation Tool...", "HEADER")
    password = load_password(args.password, args.password_file)

    target_hosts = ALL_VCF_VCENTERS if args.all_vcenters else [args.vc_host]
    log(f"Target host(s): {', '.join(target_hosts)}")

    all_results: List[ServiceRemediationResult] = []

    for host in target_hosts:
        remediator = VCenterServiceRemediator(
            vc_host=host,
            user=args.user,
            password=password,
            dry_run=args.dry_run,
        )
        try:
            res = remediator.remediate_target(
                service_name=args.service,
                force_restart=args.restart,
            )
            all_results.append(res)
        except Exception as exc:
            log(f"Unexpected error processing {host}: {exc}", "ERROR")
            err_res = ServiceRemediationResult(
                vc_host=host,
                service_name=args.service,
                error_message=str(exc),
            )
            all_results.append(err_res)

    success = print_summary_table(all_results, dry_run=args.dry_run)
    if not success and not args.dry_run:
        sys.exit(1)


if __name__ == "__main__":
    main()

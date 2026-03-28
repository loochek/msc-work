#!/usr/bin/env python3

"""
Benchmark runner for vulnerability scanners.
Scans images from manifest.json, collects timing / severity / cache metrics.
"""

import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

log = logging.getLogger(__name__)

###############################################################################

SEVERITY_MAP_TRIVY = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "UNKNOWN": "other",
}

SEVERITY_MAP_GRYPE = {
    "Critical": "critical", "High": "high", "Medium": "medium",
    "Low": "low", "Negligible": "low", "Unknown": "other",
}

SEVERITY_MAP_CLAIR = {
    "Defcon1": "critical", "Critical": "critical", "High": "high",
    "Medium": "medium", "Low": "low", "Negligible": "low", "Unknown": "other",
}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_clair_jwt(psk: str, issuer: str = "clairctl", leeway: int = 60) -> str:
    """Generate a JWT signed with Clair PSK (HS256), matching clairctl behavior."""
    key = base64.b64decode(psk)
    header = _b64url(json.dumps({"alg": "HS256"}, separators=(",", ":")).encode())
    now = int(time.time())
    claims = _b64url(json.dumps({
        "iss": issuer,
        "iat": now,
        "nbf": now - leeway,
        "exp": now + leeway,
    }, separators=(",", ":")).encode())
    payload = f"{header}.{claims}"
    sig = _b64url(hmac.new(key, payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def _clair_headers(psk: str) -> dict:
    if not psk:
        return {}
    return {"Authorization": f"Bearer {make_clair_jwt(psk)}"}


def _registry_get(url: str, headers: dict = None, verify: bool = True) -> requests.Response:
    """GET with OCI distribution token auth (handles 401 + Www-Authenticate)."""
    hdrs = dict(headers or {})
    resp = requests.get(url, headers=hdrs, verify=verify)
    if resp.status_code != 401:
        return resp

    www_auth = resp.headers.get("Www-Authenticate", "")
    if not www_auth.startswith("Bearer "):
        return resp

    params = dict(re.findall(r'(\w+)="([^"]*)"', www_auth))
    realm = params.get("realm", "")
    if not realm:
        return resp

    token_params = {}
    if "service" in params:
        token_params["service"] = params["service"]
    if "scope" in params:
        token_params["scope"] = params["scope"]

    token_resp = requests.get(realm, params=token_params, verify=verify)
    if token_resp.status_code != 200:
        return resp

    token = token_resp.json().get("token", "")
    if not token:
        return resp

    hdrs["Authorization"] = f"Bearer {token}"
    return requests.get(url, headers=hdrs, verify=verify)


def empty_vulns() -> dict:
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "other": 0}


@dataclass
class ScanResult:
    scanner: str
    image_ref: str
    wall_time_s: float = 0.0
    index_time_s: Optional[float] = None
    match_time_s: Optional[float] = None
    vulns: dict = field(default_factory=empty_vulns)
    exit_code: int = 0
    error: str = ""
    layers_fetched: list = field(default_factory=list)
    layers_scanned: list = field(default_factory=list)
    layers_cached: list = field(default_factory=list)

###############################################################################

def _parse_trivy_layer_digests(stderr: str) -> tuple[list[str], list[str]]:
    """Returns (missed_layers, all_layers) from Trivy --debug stderr."""
    # old format: "Missing diff ID in cache: sha256:..."
    # new format: "Missing diff ID in cache\tdiff_id=\"sha256:...\""
    missed = re.findall(r"Missing diff ID in cache.*?(sha256:\w+)", stderr)

    # old format: "Diff IDs: [sha256:... sha256:...]"
    # new format: "Detected diff ID\tdiff_ids=[sha256:... sha256:...]"
    all_layers = []
    all_match = re.search(r"diff_ids?=\[([^\]]+)\]", stderr, re.IGNORECASE)
    if not all_match:
        all_match = re.search(r"Diff IDs: \[([^\]]+)\]", stderr)
    if all_match:
        all_layers = re.findall(r"sha256:\w+", all_match.group(1))
    return missed, all_layers


def run_trivy(image_ref: str, insecure: bool = False, **_) -> ScanResult:
    cmd = [
        "trivy", "image", "--format", "json",
        "--debug", "--skip-db-update", "--skip-java-db-update",
    ]
    if insecure:
        cmd.append("--insecure")
    cmd.append(image_ref)

    t0 = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    wall = time.monotonic() - t0

    r = ScanResult(scanner="trivy", image_ref=image_ref,
                   wall_time_s=round(wall, 3), exit_code=proc.returncode)

    missed, all_layers = _parse_trivy_layer_digests(proc.stderr)
    missed_set = set(missed)
    r.layers_fetched = missed
    r.layers_scanned = missed
    r.layers_cached = [l for l in all_layers if l not in missed_set]

    try:
        data = json.loads(proc.stdout)
        for target in data.get("Results", []):
            for v in target.get("Vulnerabilities", []):
                sev = SEVERITY_MAP_TRIVY.get(v.get("Severity", "UNKNOWN"), "other")
                r.vulns[sev] += 1
    except (json.JSONDecodeError, KeyError) as e:
        r.error = f"parse error: {e}"

    return r

###############################################################################

def run_grype(image_ref: str, insecure: bool = False, **_) -> ScanResult:
    env = dict(os.environ)
    if insecure:
        env["SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY"] = "true"
        env["GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY"] = "true"

    r = ScanResult(scanner="grype", image_ref=image_ref)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        sbom_path = f.name

    try:
        # indexing phase (syft)
        t0 = time.monotonic()
        proc_syft = subprocess.run(
            ["syft", image_ref, "-o", f"json={sbom_path}"],
            capture_output=True, text=True, env=env,
        )
        r.index_time_s = round(time.monotonic() - t0, 3)

        if proc_syft.returncode != 0:
            r.error = f"syft failed: {proc_syft.stderr[:500]}"
            r.exit_code = proc_syft.returncode
            return r

        # matching phase (grype from SBOM)
        t0 = time.monotonic()
        proc_grype = subprocess.run(
            ["grype", f"sbom:{sbom_path}", "-o", "json"],
            capture_output=True, text=True, env=env,
        )
        r.match_time_s = round(time.monotonic() - t0, 3)

        r.wall_time_s = round(r.index_time_s + r.match_time_s, 3)
        r.exit_code = proc_grype.returncode

        # syft/grype have no layer cache — every layer is fetched and scanned
        try:
            sbom = json.loads(Path(sbom_path).read_text())
            for layer in sbom.get("source", {}).get("metadata", {}).get("layers", []):
                digest = layer.get("digest", "")
                if digest:
                    r.layers_fetched.append(digest)
                    r.layers_scanned.append(digest)
        except Exception:
            pass

        try:
            data = json.loads(proc_grype.stdout)
            for m in data.get("matches", []):
                sev = m.get("vulnerability", {}).get("severity", "Unknown")
                r.vulns[SEVERITY_MAP_GRYPE.get(sev, "other")] += 1
        except (json.JSONDecodeError, KeyError) as e:
            r.error = f"grype parse error: {e}"

    finally:
        Path(sbom_path).unlink(missing_ok=True)

    return r

###############################################################################

def _parse_clair_logs(logs: str) -> tuple[list[str], list[str], list[str]]:
    """Returns (fetched, scanned, cached) layer digests from Clair indexer logs."""
    fetched = list(set(re.findall(r"layer fetch start.*?layer=(sha256:\w+)", logs)))
    scanned = list(set(re.findall(r"scan start.*?layer=(sha256:\w+)", logs)))
    cached = list(set(re.findall(r"layer already scanned.*?layer=(sha256:\w+)", logs)))
    return fetched, scanned, cached


def run_clair(image_ref: str, insecure: bool = False,
              clair_url: str = "", registry: str = "",
              clair_indexer_container: str = "", clair_psk: str = "", **_) -> ScanResult:
    r = ScanResult(scanner="clair", image_ref=image_ref)
    verify = not insecure
    auth = _clair_headers(clair_psk)

    # fetch OCI manifest from registry to build Clair payload
    ref = image_ref
    if ref.startswith(registry + "/"):
        ref = ref[len(registry) + 1:]
    name, tag = ref.rsplit(":", 1) if ":" in ref else (ref, "latest")
    base_url = f"https://{registry}"

    try:
        resp = _registry_get(
            f"{base_url}/v2/{name}/manifests/{tag}",
            headers={"Accept": ", ".join([
                "application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.v2+json",
            ])},
            verify=verify,
        )
        resp.raise_for_status()
        manifest = resp.json()
        manifest_digest = resp.headers.get("Docker-Content-Digest", "")
    except Exception as e:
        r.error = f"failed to fetch manifest: {e}"
        r.exit_code = 1
        return r

    payload = {
        "hash": manifest_digest,
        "layers": [{
            "hash": layer["digest"],
            "uri": f"{base_url}/v2/{name}/blobs/{layer['digest']}",
            "headers": {},
        } for layer in manifest.get("layers", [])],
    }

    log_since = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # indexing
    t0 = time.monotonic()
    try:
        resp = requests.post(
            f"{clair_url}/indexer/api/v1/index_report",
            json=payload, headers=auth, verify=verify,
        )
        r.index_time_s = round(time.monotonic() - t0, 3)
        if resp.status_code not in (200, 201):
            r.error = f"index failed: {resp.status_code} {resp.text[:300]}"
            r.exit_code = 1
            return r
    except Exception as e:
        r.error = f"index request failed: {e}"
        r.exit_code = 1
        return r

    # matching
    t0 = time.monotonic()
    try:
        resp = requests.get(
            f"{clair_url}/matcher/api/v1/vulnerability_report/{manifest_digest}",
            headers=auth, verify=verify,
        )
        r.match_time_s = round(time.monotonic() - t0, 3)
        r.wall_time_s = round(r.index_time_s + r.match_time_s, 3)

        if resp.status_code != 200:
            r.error = f"match failed: {resp.status_code} {resp.text[:300]}"
            r.exit_code = 1
            return r

        vuln_report = resp.json()
        for _, vuln in vuln_report.get("vulnerabilities", {}).items():
            sev = vuln.get("normalized_severity", "Unknown")
            r.vulns[SEVERITY_MAP_CLAIR.get(sev, "other")] += 1
    except Exception as e:
        r.error = f"match request failed: {e}"
        r.exit_code = 1
        return r

    # parse indexer container logs for layer-level cache info
    if clair_indexer_container:
        time.sleep(0.5)
        proc = subprocess.run(
            ["docker", "logs", clair_indexer_container, "--since", log_since],
            capture_output=True, text=True,
        )
        logs = proc.stderr + proc.stdout
        r.layers_fetched, r.layers_scanned, r.layers_cached = _parse_clair_logs(logs)

    return r

###############################################################################

SCANNERS = {
    "trivy": run_trivy,
    "grype": run_grype,
    "clair": run_clair,
}


def clear_clair_cache(images: list[dict], registry: str,
                      clair_url: str, insecure: bool, clair_psk: str = ""):
    """Delete all index reports from Clair via bulk DELETE API."""
    verify = not insecure
    auth = _clair_headers(clair_psk)

    # collect manifest digests by fetching from registry
    digests = []
    for img in images:
        ref = img["ref"]
        if ref.startswith(registry + "/"):
            ref = ref[len(registry) + 1:]
        name, tag = ref.rsplit(":", 1) if ":" in ref else (ref, "latest")

        try:
            resp = _registry_get(
                f"https://{registry}/v2/{name}/manifests/{tag}",
                headers={"Accept": ", ".join([
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                ])},
                verify=verify,
            )
            digest = resp.headers.get("Docker-Content-Digest", "")
            if digest:
                digests.append(digest)
        except Exception as e:
            log.warning(f"Failed to get digest for {img['ref']}: {e}")

    if not digests:
        return

    log.info(f"Clearing Clair index cache ({len(digests)} manifests)")
    try:
        resp = requests.delete(
            f"{clair_url}/indexer/api/v1/index_report",
            json=digests,
            headers={"Content-Type": "application/vnd.clair.bulk_delete.v1+json", **auth},
            verify=verify,
        )
        if resp.status_code == 200:
            log.info(f"Clair cache cleared")
        else:
            log.warning(f"Clair cache clear: {resp.status_code} {resp.text[:200]}")
    except Exception as e:
        log.warning(f"Failed to clear Clair cache: {e}")


def run_all(images: list[dict], scanners: list[str], **kwargs) -> list[dict]:
    results = []
    total = len(images) * len(scanners)
    idx = 0

    for scanner in scanners:
        log.info(f"=== {scanner} ===")
        for img in images:
            idx += 1
            ref = img["ref"]
            log.info(f"[{idx}/{total}] {scanner}: {ref}")

            r = SCANNERS[scanner](ref, **kwargs)

            cached = len(r.layers_cached)
            fetched = len(r.layers_fetched)
            log.info(
                f"  {r.wall_time_s:.1f}s  "
                f"vulns={sum(r.vulns.values())}  "
                f"layers: {fetched} fetched, {cached} cached  "
                f"exit={r.exit_code}"
                f"{'  ERR: ' + r.error if r.error else ''}"
            )
            results.append(asdict(r))

    return results

###############################################################################

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run vulnerability scanner benchmarks on a set of images"
    )
    p.add_argument("--manifest", type=Path, required=True,
                   help="Path to manifest.json from generate_images.py")
    p.add_argument("--scanners", nargs="+", default=["trivy", "grype", "clair"],
                   choices=["trivy", "grype", "clair"],
                   help="Scanners to benchmark (default: trivy grype)")
    p.add_argument("--clair-url", default="localhost:6060",
                   help="Clair API base URL (required for --scanners clair)")
    p.add_argument("--clair-indexer-container", default="clair-indexer",
                   help="Docker container name for Clair indexer (for log parsing)")
    p.add_argument("--clair-psk", default="",
                   help="Base64-encoded PSK for Clair JWT auth (from clair config auth.psk.key)")
    p.add_argument("--insecure", action="store_true",
                   help="Skip TLS verification for registry and Clair")
    p.add_argument("--output", type=Path, default=Path("results.json"),
                   help="Output file for results (default: results.json)")
    p.add_argument("--cold", action="store_true",
                   help="Clear scanner caches before running (cold scan)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose output")
    return p.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    manifest = json.loads(args.manifest.read_text())
    images = manifest["images"]
    registry = manifest["params"]["registry"]

    log.info(f"Loaded {len(images)} images from {args.manifest}")

    if "clair" in args.scanners and not args.clair_url:
        log.error("--clair-url required when using --scanners clair")
        return

    if args.cold:
        if "trivy" in args.scanners:
            log.info("Clearing Trivy scan cache")
            subprocess.run(["trivy", "clean", "--scan-cache"], capture_output=True)
        if "clair" in args.scanners:
            clear_clair_cache(images, registry, args.clair_url,
                              args.insecure, args.clair_psk)

    results = run_all(
        images=images,
        scanners=args.scanners,
        insecure=args.insecure,
        clair_url=args.clair_url,
        registry=registry,
        clair_indexer_container=args.clair_indexer_container,
        clair_psk=args.clair_psk,
    )

    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "params": {
            "manifest": str(args.manifest),
            "scanners": args.scanners,
            "cold": args.cold,
        },
        "results": results,
    }

    args.output.write_text(json.dumps(output, indent=2) + "\n")
    log.info(f"Results saved to {args.output}")

    for scanner in args.scanners:
        sc = [r for r in results if r["scanner"] == scanner]
        times = [r["wall_time_s"] for r in sc]
        vulns = sum(sum(r["vulns"].values()) for r in sc)
        errs = sum(1 for r in sc if r["error"])
        if times:
            log.info(
                f"{scanner}: {len(sc)} images, "
                f"total={sum(times):.1f}s, avg={sum(times)/len(times):.1f}s, "
                f"vulns={vulns}, errors={errs}"
            )


if __name__ == "__main__":
    main()

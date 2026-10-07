#!/usr/bin/env python3
"""
RHACS / StackRox asset collector
================================

Pulls every asset RHACS Central knows about and writes ONE normalized JSON
file that the CVE-impact webapp (and anything else, e.g. OpenSearch) can read.

Collected objects                       RHACS API used
-------------------------------------   ------------------------------------------
Clusters                                GET /v1/clusters
Namespaces                              GET /v1/namespaces
Deployments (workloads)                 GET /v1/export/deployments   (stream, 4.3+)
Pods (deployment -> node placement)     GET /v1/export/pods          (stream, 4.3+)
Images + components + CVEs              GET /v1/export/images        (stream, 4.3+)
Nodes + OS components + CVEs            GET /v1/export/nodes         (stream, 4.3+)

If a streaming export endpoint is missing (older Central), the script falls
back to the classic paginated APIs (/v1/deployments, /v1/images, /v1/pods,
/v1/nodes/{clusterId}).

Auth: an API token (Platform Configuration > Integrations > API Token).
A token with the built-in "Analyst" role (read-only) is enough.

Usage
-----
    export ROX_CENTRAL_ADDRESS=central.example.com:443
    export ROX_API_TOKEN=eyJ...
    python rhacs_collector.py --out ../data/assets.json --csv ../data/cve_impact.csv

    # self-signed Central cert:
    python rhacs_collector.py --ca-cert /path/to/central-ca.pem
    python rhacs_collector.py --insecure          # lab only

Output schema (schemaVersion 1)
-------------------------------
{
  "meta":        {...collection info + counts...},
  "clusters":    [ {id, name, type, k8sVersion, ...} ],
  "namespaces":  [ {id, name, clusterId, clusterName, labels, ...} ],
  "nodes":       [ {id, name, clusterId, os, kernel, components:[{name,version,vulns:[{cve,fixedBy}]}]} ],
  "deployments": [ {id, name, namespace, clusterId, containers:[{name,image,imageId}], nodes:[...], ...} ],
  "images":      [ {id, fullName, names:[...], os, components:[{name,version,source,vulns:[...]}]} ],
  "cves":        { "CVE-2024-1234": {severity, cvss, summary, link, publishedOn, epss, ...} }
}
Relationships are expressed by IDs (deployment.containers[].imageId -> images[].id,
deployment.clusterId -> clusters[].id, component.vulns[].cve -> cves{} key, ...).
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

SCHEMA_VERSION = 1
log = logging.getLogger("rhacs-collector")

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
SEVERITY_MAP = {
    "CRITICAL_VULNERABILITY_SEVERITY": "Critical",
    "IMPORTANT_VULNERABILITY_SEVERITY": "Important",
    "MODERATE_VULNERABILITY_SEVERITY": "Moderate",
    "LOW_VULNERABILITY_SEVERITY": "Low",
    "UNKNOWN_VULNERABILITY_SEVERITY": "Unknown",
}
SEVERITY_RANK = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1, "Unknown": 0}

EXPOSURE_RANK = {"EXTERNAL": 4, "ROUTE": 3, "NODE": 2, "HOST": 2, "INTERNAL": 1, "UNSET": 0}


def norm_severity(value: Optional[str], cvss: Optional[float] = None) -> str:
    if value and value in SEVERITY_MAP:
        return SEVERITY_MAP[value]
    if value and value.title() in SEVERITY_RANK:
        return value.title()
    # derive from CVSS when severity is missing (older Central versions)
    if cvss is None:
        return "Unknown"
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "Important"
    if cvss >= 4.0:
        return "Moderate"
    if cvss > 0:
        return "Low"
    return "Unknown"


def to_float(v: Any) -> Optional[float]:
    try:
        return round(float(v), 2) if v is not None and v != "" else None
    except (TypeError, ValueError):
        return None


def image_full_name(name: Optional[dict]) -> str:
    if not name:
        return ""
    if name.get("fullName"):
        return name["fullName"]
    reg, remote, tag = name.get("registry", ""), name.get("remote", ""), name.get("tag", "")
    full = f"{reg}/{remote}" if reg else remote
    return f"{full}:{tag}" if tag else full


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# --------------------------------------------------------------------------- #
# API client
# --------------------------------------------------------------------------- #
class EndpointMissing(Exception):
    """Raised when Central does not implement an endpoint (older version)."""


class RhacsClient:
    def __init__(self, central: str, token: str, verify: Any = True,
                 timeout: int = 120, page_size: int = 500):
        if not central.startswith(("http://", "https://")):
            central = "https://" + central
        self.base = central.rstrip("/")
        self.timeout = timeout
        self.page_size = page_size
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {token}",
                               "Accept": "application/json"})
        self.s.verify = verify
        retry = Retry(total=4, backoff_factor=1.5,
                      status_forcelist=(429, 500, 502, 503, 504),
                      allowed_methods=frozenset(["GET"]))
        self.s.mount("https://", HTTPAdapter(max_retries=retry))
        self.s.mount("http://", HTTPAdapter(max_retries=retry))

    # -- plain GET -----------------------------------------------------------
    def get(self, path: str, params: Optional[dict] = None) -> dict:
        r = self.s.get(self.base + path, params=params, timeout=self.timeout)
        if r.status_code in (404, 501):
            raise EndpointMissing(path)
        if r.status_code in (401, 403):
            raise SystemExit(f"[!] {r.status_code} on {path}: token invalid or lacks read permission")
        r.raise_for_status()
        return r.json()

    # -- streaming export (/v1/export/*) -------------------------------------
    def stream(self, path: str, key: str, query: Optional[str] = None) -> Iterator[dict]:
        """Yield objects from a gRPC-gateway server-streaming endpoint.

        Each line is {"result": {"<key>": {...}}} or {"error": {...}}.
        """
        params = {"timeout": self.timeout * 10}
        if query:
            params["query"] = query
        with self.s.get(self.base + path, params=params, stream=True,
                        timeout=(30, self.timeout * 10)) as r:
            if r.status_code in (404, 501):
                raise EndpointMissing(path)
            if r.status_code in (401, 403):
                raise SystemExit(f"[!] {r.status_code} on {path}: token invalid or lacks read permission")
            r.raise_for_status()
            for raw in r.iter_lines(decode_unicode=True):
                if not raw or not raw.strip():
                    continue
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    log.warning("Unparseable stream line on %s (truncated): %s", path, raw[:200])
                    continue
                if "error" in msg:
                    raise RuntimeError(f"Stream error on {path}: {msg['error']}")
                obj = (msg.get("result") or {}).get(key)
                if obj:
                    yield obj

    # -- classic pagination --------------------------------------------------
    def paginate(self, path: str, list_key: str, query: Optional[str] = None) -> Iterator[dict]:
        offset = 0
        while True:
            params = {"pagination.limit": self.page_size, "pagination.offset": offset}
            if query:
                params["query"] = query
            items = self.get(path, params).get(list_key) or []
            yield from items
            if len(items) < self.page_size:
                return
            offset += self.page_size

    # -- high level fetchers -------------------------------------------------
    def clusters(self) -> List[dict]:
        return self.get("/v1/clusters").get("clusters") or []

    def namespaces(self) -> List[dict]:
        return self.get("/v1/namespaces").get("namespaces") or []

    def deployments(self, query=None) -> Iterator[dict]:
        try:
            yield from self.stream("/v1/export/deployments", "deployment", query)
        except EndpointMissing:
            log.info("  export API missing -> falling back to /v1/deployments + per-id GET")
            for d in self.paginate("/v1/deployments", "deployments", query):
                yield self.get(f"/v1/deployments/{d['id']}")

    def pods(self, query=None) -> Iterator[dict]:
        try:
            yield from self.stream("/v1/export/pods", "pod", query)
        except EndpointMissing:
            log.info("  export API missing -> falling back to /v1/pods")
            yield from self.paginate("/v1/pods", "pods", query)

    def images(self, query=None) -> Iterator[dict]:
        try:
            yield from self.stream("/v1/export/images", "image", query)
        except EndpointMissing:
            log.info("  export API missing -> falling back to /v1/images + per-id GET")
            for i in self.paginate("/v1/images", "images", query):
                try:
                    yield self.get(f"/v1/images/{i['id']}")
                except EndpointMissing:
                    log.warning("  image %s vanished during collection", i.get("id"))

    def sbom(self, image_name: str, endpoint: str = "/api/v1/images/sbom") -> dict:
        """Ask Central (Scanner V4, RHACS 4.7+) for an SPDX 2.3 SBOM of an already-scanned image."""
        r = self.s.post(self.base + endpoint, json={"imageName": image_name, "force": False},
                        timeout=self.timeout * 2)
        if r.status_code in (404, 501):
            raise EndpointMissing(endpoint)
        r.raise_for_status()
        return r.json()

    def nodes(self, cluster_ids: Iterable[str], query=None) -> Iterator[dict]:
        try:
            yield from self.stream("/v1/export/nodes", "node", query)
        except EndpointMissing:
            log.info("  export API missing -> falling back to /v1/nodes/{clusterId}")
            for cid in cluster_ids:
                for n in self.get(f"/v1/nodes/{cid}").get("nodes") or []:
                    yield n


# --------------------------------------------------------------------------- #
# Normalizers (raw RHACS objects -> compact, linkable records)
# --------------------------------------------------------------------------- #
class CveCatalog:
    """Global CVE dictionary; keeps the most severe view of each CVE."""

    def __init__(self):
        self.cves: Dict[str, dict] = {}

    def add(self, v: dict, asset_type: str) -> Optional[str]:
        # Image/Embedded vulns use top-level fields; NodeVulnerability uses cveBaseInfo
        base = v.get("cveBaseInfo") or {}
        cve_id = v.get("cve") or base.get("cve")
        if not cve_id:
            return None
        cvss = to_float(v.get("cvss"))
        if cvss is None:
            cvss = to_float((v.get("cvssV3") or base.get("cvssV3") or {}).get("score"))
        sev = norm_severity(v.get("severity"), cvss)
        epss = v.get("epss") or base.get("epss") or {}
        advisory = v.get("advisory") or {}
        rec = {
            "severity": sev,
            "cvss": cvss,
            "cvssVersion": v.get("scoreVersion") or ("V3" if v.get("cvssV3") or base.get("cvssV3") else None),
            "nvdCvss": to_float(v.get("nvdCvss")),
            "summary": (v.get("summary") or base.get("summary") or "").strip(),
            "link": v.get("link") or base.get("link") or "",
            "publishedOn": v.get("publishedOn") or base.get("publishedOn"),
            "epssProbability": to_float(epss.get("epssProbability")),
            "epssPercentile": to_float(epss.get("epssPercentile")),
            "advisory": advisory.get("name") or None,
            "assetTypes": [asset_type],
        }
        cur = self.cves.get(cve_id)
        if cur is None:
            self.cves[cve_id] = rec
        else:
            if SEVERITY_RANK[sev] > SEVERITY_RANK[cur["severity"]]:
                cur["severity"] = sev
            if cvss and (cur["cvss"] or 0) < cvss:
                cur["cvss"] = cvss
            for k in ("summary", "link", "publishedOn", "epssProbability", "epssPercentile", "advisory"):
                if not cur.get(k) and rec.get(k):
                    cur[k] = rec[k]
            if asset_type not in cur["assetTypes"]:
                cur["assetTypes"].append(asset_type)
        return cve_id


# --------------------------------------------------------------------------- #
# SBOM helpers - package URL (purl) derivation + SPDX parsing
# --------------------------------------------------------------------------- #
from urllib.parse import quote as _q

LANG_PURL = {"JAVA": "maven", "PYTHON": "pypi", "GO": "golang", "GOLANG": "golang", "NODEJS": "npm",
             "NPM": "npm", "RUBY": "gem", "GEM": "gem", "DOTNETCORERUNTIME": "nuget", "DOTNET": "nuget",
             "RUST": "cargo", "PHP": "composer"}


def os_purl(os_name: str):
    """Map a scanner OS string (rhel:9, ubuntu:22.04, alpine:3.18, ...) to (purl type, namespace)."""
    o = (os_name or "").lower()
    for key, typ, ns in (("rhel", "rpm", "redhat"), ("red hat", "rpm", "redhat"), ("rhcos", "rpm", "redhat"),
                         ("coreos", "rpm", "redhat"), ("centos", "rpm", "centos"), ("fedora", "rpm", "fedora"),
                         ("rocky", "rpm", "rocky"), ("alma", "rpm", "almalinux"), ("amzn", "rpm", "amazon"),
                         ("amazon", "rpm", "amazon"), ("sles", "rpm", "suse"), ("opensuse", "rpm", "opensuse"),
                         ("ubuntu", "deb", "ubuntu"), ("debian", "deb", "debian"), ("alpine", "apk", "alpine"),
                         ("wolfi", "apk", "wolfi"), ("photon", "rpm", "photon")):
        if key in o:
            return typ, ns
    return "generic", ""


def derive_purl(name: str, version: str, source: str, os_name: str) -> str:
    if not name:
        return ""
    src = (source or "OS").upper()
    ver = "@" + _q(version, safe="") if version else ""
    if src in LANG_PURL:
        typ = LANG_PURL[src]
        if typ == "maven" and ":" in name:          # group:artifact
            g, a = name.split(":", 1)
            return f"pkg:maven/{_q(g, safe='.')}/{_q(a, safe='')}{ver}"
        if typ == "golang":
            return f"pkg:golang/{_q(name, safe='/.')}{ver}"
        if typ == "npm" and name.startswith("@"):
            return f"pkg:npm/{_q(name, safe='/')}{ver}"
        return f"pkg:{typ}/{_q(name, safe='')}{ver}"
    typ, ns = os_purl(os_name)
    return f"pkg:{typ}/{ns + '/' if ns else ''}{_q(name, safe='')}{ver}"


def parse_spdx(doc: dict) -> Dict[tuple, dict]:
    """Return {(name, version): {purl, license, supplier, ...}} from an SPDX 2.x JSON document."""
    out = {}
    for p in doc.get("packages") or []:
        purl = next((r.get("referenceLocator") for r in p.get("externalRefs") or []
                     if (r.get("referenceType") or "").lower() == "purl"), "")
        cpe = next((r.get("referenceLocator") for r in p.get("externalRefs") or []
                    if "cpe" in (r.get("referenceType") or "").lower()), "")
        lic = p.get("licenseConcluded") or p.get("licenseDeclared") or ""
        if lic in ("NOASSERTION", "NONE"):
            lic = p.get("licenseDeclared") if p.get("licenseDeclared") not in (None, "NOASSERTION", "NONE") else ""
        sup = p.get("supplier") or ""
        out[(p.get("name", ""), p.get("versionInfo", ""))] = {
            "purl": purl, "cpe": cpe, "license": lic or "",
            "supplier": "" if sup == "NOASSERTION" else sup.replace("Organization: ", "").replace("Person: ", ""),
            "spdxId": p.get("SPDXID"), "purpose": p.get("primaryPackagePurpose") or "",
            "downloadLocation": "" if p.get("downloadLocation") in (None, "NOASSERTION", "NONE") else p.get("downloadLocation"),
        }
    return out


def norm_components(components: List[dict], cat: CveCatalog, asset_type: str, os_name: str = "") -> List[dict]:
    out = []
    for c in components or []:
        vulns = []
        for v in (c.get("vulns") or []) + (c.get("vulnerabilities") or []):
            cve_id = cat.add(v, asset_type)
            if not cve_id:
                continue
            vulns.append({
                "cve": cve_id,
                "fixedBy": v.get("fixedBy") or "",
                "state": v.get("state") or ("SNOOZED" if v.get("snoozed") else "OBSERVED"),
            })
        # de-dup (node components may carry both vulns + vulnerabilities)
        seen, uniq = set(), []
        for v in vulns:
            if v["cve"] not in seen:
                seen.add(v["cve"])
                uniq.append(v)
        name, version, source = c.get("name", ""), c.get("version", ""), c.get("source") or ""
        out.append({
            "name": name,
            "version": version,
            "source": source,
            "location": c.get("location") or "",
            "layerIndex": c.get("layerIndex"),
            "license": (c.get("license") or {}).get("name", "") if isinstance(c.get("license"), dict) else "",
            "purl": derive_purl(name, version, source, os_name),
            "purlSource": "derived",          # becomes "sbom" when enriched from an RHACS SPDX document
            "supplier": "",
            "vulns": uniq,
        })
    return out


def norm_cluster(c: dict) -> dict:
    st = c.get("status") or {}
    om = st.get("orchestratorMetadata") or {}
    pm = st.get("providerMetadata") or {}
    provider = next((k for k in ("aws", "google", "azure") if pm.get(k)), "")
    return {
        "id": c.get("id"),
        "name": c.get("name"),
        "type": c.get("type"),
        "k8sVersion": om.get("version"),
        "openshiftVersion": om.get("openshiftVersion"),
        "sensorVersion": st.get("sensorVersion"),
        "health": (c.get("healthStatus") or {}).get("overallHealthStatus"),
        "provider": provider,
        "region": pm.get("region"),
        "labels": c.get("labels") or {},
    }


def norm_namespace(n: dict) -> dict:
    md = n.get("metadata") or n
    return {
        "id": md.get("id"),
        "name": md.get("name"),
        "clusterId": md.get("clusterId"),
        "clusterName": md.get("clusterName"),
        "labels": md.get("labels") or {},
        "created": md.get("creationTime"),
        "deploymentCount": n.get("numDeployments"),
        "networkPolicyCount": n.get("numNetworkPolicies"),
    }


def norm_node(n: dict, cat: CveCatalog) -> dict:
    scan = n.get("scan") or {}
    return {
        "id": n.get("id"),
        "name": n.get("name"),
        "clusterId": n.get("clusterId"),
        "clusterName": n.get("clusterName"),
        "os": n.get("osImage") or scan.get("operatingSystem"),
        "kernel": n.get("kernelVersion"),
        "runtime": n.get("containerRuntimeVersion") or (n.get("containerRuntime") or {}).get("version"),
        "kubelet": n.get("kubeletVersion"),
        "internalIps": n.get("internalIpAddresses") or [],
        "externalIps": n.get("externalIpAddresses") or [],
        "labels": n.get("labels") or {},
        "joinedAt": n.get("joinedAt"),
        "scanTime": scan.get("scanTime"),
        "scanNotes": scan.get("notes") or n.get("notes") or [],
        "components": norm_components(scan.get("components"), cat, "NODE",
                                      n.get("osImage") or scan.get("operatingSystem") or ""),
    }


def norm_image(i: dict, cat: CveCatalog) -> dict:
    scan = i.get("scan") or {}
    name = i.get("name") or {}
    v1 = ((i.get("metadata") or {}).get("v1")) or {}
    names = sorted({image_full_name(n) for n in (i.get("names") or [])} | {image_full_name(name)} - {""})
    return {
        "id": i.get("id"),
        "fullName": image_full_name(name),
        "names": names,
        "registry": name.get("registry"),
        "remote": name.get("remote"),
        "tag": name.get("tag"),
        "os": scan.get("operatingSystem"),
        "created": v1.get("created"),
        "scanTime": scan.get("scanTime"),
        "scanner": scan.get("dataSource", {}).get("name") if isinstance(scan.get("dataSource"), dict) else None,
        "notes": i.get("notes") or [],
        "riskScore": to_float(i.get("riskScore")),
        "lastUpdated": i.get("lastUpdated"),
        "components": norm_components(scan.get("components"), cat, "IMAGE", scan.get("operatingSystem") or ""),
        "sbom": {"available": False},
    }


def norm_deployment(d: dict) -> dict:
    containers, privileged = [], False
    for c in d.get("containers") or []:
        img = c.get("image") or {}
        sc = c.get("securityContext") or {}
        priv = bool(sc.get("privileged"))
        privileged |= priv
        containers.append({
            "name": c.get("name"),
            "image": image_full_name(img.get("name")),
            "imageId": img.get("id") or "",
            "privileged": priv,
            "runAsRoot": not sc.get("runAsNonRoot", False) if sc else None,
        })
    ports, top_exposure = [], "UNSET"
    for p in d.get("ports") or []:
        exp = p.get("exposure") or "UNSET"
        for info in p.get("exposureInfos") or []:
            lvl = info.get("level") or exp
            if EXPOSURE_RANK.get(lvl, 0) > EXPOSURE_RANK.get(exp, 0):
                exp = lvl
        if EXPOSURE_RANK.get(exp, 0) > EXPOSURE_RANK.get(top_exposure, 0):
            top_exposure = exp
        ports.append({"port": p.get("containerPort"), "protocol": p.get("protocol"), "exposure": exp})
    return {
        "id": d.get("id"),
        "name": d.get("name"),
        "type": d.get("type"),
        "namespace": d.get("namespace"),
        "namespaceId": d.get("namespaceId"),
        "clusterId": d.get("clusterId"),
        "clusterName": d.get("clusterName"),
        "labels": d.get("labels") or {},
        "serviceAccount": d.get("serviceAccount"),
        "riskScore": to_float(d.get("riskScore")),
        "created": d.get("created"),
        "inactive": bool(d.get("inactive")),
        "hostNetwork": bool(d.get("hostNetwork")),
        "privileged": privileged,
        "exposure": top_exposure,
        "ports": ports,
        "containers": containers,
        "nodes": [],      # filled from pods
        "podCount": 0,    # filled from pods
    }


# --------------------------------------------------------------------------- #
# Collection pipeline
# --------------------------------------------------------------------------- #
def timed(label: str, fn: Callable[[], List[dict]]) -> List[dict]:
    t0 = time.time()
    log.info("Collecting %s ...", label)
    out = fn()
    log.info("  %-12s %6d  (%.1fs)", label, len(out), time.time() - t0)
    return out


def enrich_sboms(client: RhacsClient, images: List[dict], sbom_dir: str, endpoint: str,
                 workers: int = 4) -> dict:
    """Fetch an official SPDX SBOM per image, store it, merge purl/license/supplier into components."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    os.makedirs(sbom_dir, exist_ok=True)
    stats = {"requested": len(images), "ok": 0, "failed": 0, "unsupported": False}

    def fetch(img):
        return img, client.sbom(img["fullName"], endpoint)

    # probe once so an older Central fails fast instead of N times
    if images:
        try:
            first = fetch(images[0])
        except EndpointMissing:
            log.warning("  SBOM endpoint %s not available (needs RHACS 4.7+ with Scanner V4) - using derived purls", endpoint)
            stats["unsupported"] = True
            return stats
        except Exception as e:  # noqa
            log.warning("  SBOM probe failed: %s", e)
            first = None
    else:
        return stats

    def apply(img, doc):
        fname = img["id"].replace("sha256:", "") + ".spdx.json"
        with open(os.path.join(sbom_dir, fname), "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        pk = parse_spdx(doc)
        by_name = {}
        for (n, v), info in pk.items():
            by_name.setdefault(n, info)
        matched = set()
        for comp in img["components"]:
            info = pk.get((comp["name"], comp["version"])) or by_name.get(comp["name"])
            if not info:
                continue
            matched.add((comp["name"], comp["version"]))
            if info["purl"]:
                comp["purl"], comp["purlSource"] = info["purl"], "sbom"
            comp["license"] = info["license"] or comp["license"]
            comp["supplier"] = info["supplier"]
            comp["cpe"] = info["cpe"]
        # packages present in the SBOM but not in the vuln scan (e.g. no known CVEs)
        for (n, v), info in pk.items():
            if (n, v) in matched or info["purpose"] in ("CONTAINER", "OPERATING-SYSTEM") or not v:
                continue
            if n == img.get("remote") or n == img["fullName"]:
                continue
            img["components"].append({"name": n, "version": v, "source": "SBOM", "location": "", "layerIndex": None,
                                      "license": info["license"], "purl": info["purl"], "purlSource": "sbom",
                                      "supplier": info["supplier"], "cpe": info["cpe"], "vulns": []})
        img["sbom"] = {"available": True, "format": doc.get("spdxVersion", "SPDX"), "file": fname,
                       "created": (doc.get("creationInfo") or {}).get("created"), "packages": len(pk)}

    jobs = images[1:] if first else images
    if first:
        apply(*first)
        stats["ok"] += 1
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fetch, i): i for i in jobs}
        for f in as_completed(futs):
            try:
                apply(*f.result())
                stats["ok"] += 1
            except Exception as e:  # noqa
                stats["failed"] += 1
                log.debug("  SBOM failed for %s: %s", futs[f]["fullName"], e)
    return stats


def collect(client: RhacsClient, query: Optional[str], skip_nodes: bool, skip_pods: bool,
            sbom: bool = False, sbom_all: bool = False, sbom_dir: str = "sbom",
            sbom_endpoint: str = "/api/v1/images/sbom") -> dict:
    cat = CveCatalog()
    started = now_iso()

    clusters = timed("clusters", lambda: [norm_cluster(c) for c in client.clusters()])
    namespaces = timed("namespaces", lambda: [norm_namespace(n) for n in client.namespaces()])
    deployments = timed("deployments", lambda: [norm_deployment(d) for d in client.deployments(query)])
    images = timed("images", lambda: [norm_image(i, cat) for i in client.images(query)])
    nodes = [] if skip_nodes else timed(
        "nodes", lambda: [norm_node(n, cat) for n in client.nodes([c["id"] for c in clusters])])
    pods = [] if skip_pods else timed("pods", lambda: list(client.pods(query)))

    # --- link: deployment -> nodes (via pod live instances) -----------------
    dep_by_id = {d["id"]: d for d in deployments}
    for p in pods:
        d = dep_by_id.get(p.get("deploymentId"))
        if not d:
            continue
        d["podCount"] += 1
        for inst in p.get("liveInstances") or []:
            node = (inst.get("instanceId") or {}).get("node")
            if node and node not in d["nodes"]:
                d["nodes"].append(node)

    # --- link: container image name -> image id (tags without digest) -------
    by_name = {}
    for img in images:
        for n in img["names"]:
            by_name.setdefault(n, img["id"])
    unresolved = 0
    for d in deployments:
        for c in d["containers"]:
            if not c["imageId"] and c["image"] in by_name:
                c["imageId"] = by_name[c["image"]]
            if not c["imageId"]:
                unresolved += 1

    # --- SBOM enrichment -----------------------------------------------------
    sbom_stats = {"enabled": sbom}
    if sbom:
        deployed = {c["imageId"] for d in deployments for c in d["containers"] if c["imageId"]}
        targets = [i for i in images if i["components"] and (sbom_all or i["id"] in deployed)]
        t0 = time.time()
        log.info("Fetching SBOMs for %d images ...", len(targets))
        sbom_stats.update(enrich_sboms(client, targets, sbom_dir, sbom_endpoint))
        log.info("  sboms        ok=%d failed=%d  (%.1fs)", sbom_stats.get("ok", 0), sbom_stats.get("failed", 0),
                 time.time() - t0)

    return {
        "meta": {
            "schemaVersion": SCHEMA_VERSION,
            "sbom": sbom_stats,
            "sbomDir": os.path.abspath(sbom_dir) if sbom else None,
            "source": "Red Hat Advanced Cluster Security",
            "central": client.base,
            "collectionStarted": started,
            "collectedAt": now_iso(),
            "scopeQuery": query,
            "counts": {
                "clusters": len(clusters), "namespaces": len(namespaces), "nodes": len(nodes),
                "deployments": len(deployments), "pods": len(pods), "images": len(images),
                "cves": len(cat.cves), "unresolvedContainerImages": unresolved,
            },
        },
        "clusters": clusters,
        "namespaces": namespaces,
        "nodes": nodes,
        "deployments": deployments,
        "images": images,
        "cves": cat.cves,
    }


# --------------------------------------------------------------------------- #
# Flat CSV (one row per CVE x component x asset) - handy for SIEM ingestion
# --------------------------------------------------------------------------- #
CSV_FIELDS = ["cve", "severity", "cvss", "epss_probability", "fixable", "fixed_by",
              "component", "component_version", "purl", "license", "asset_type", "cluster", "namespace",
              "deployment", "deployment_id", "image", "image_id", "node", "exposure",
              "privileged", "collected_at"]


def write_csv(data: dict, path: str) -> int:
    cves = data["cves"]
    cl_name = {c["id"]: c["name"] for c in data["clusters"]}
    deps_by_img: Dict[str, List[dict]] = {}
    for d in data["deployments"]:
        for c in d["containers"]:
            if c["imageId"]:
                deps_by_img.setdefault(c["imageId"], []).append(d)
    ts = data["meta"]["collectedAt"]
    rows = 0
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()

        def base(v, comp):
            c = cves.get(v["cve"], {})
            return {"cve": v["cve"], "severity": c.get("severity"), "cvss": c.get("cvss"),
                    "epss_probability": c.get("epssProbability"), "fixable": bool(v["fixedBy"]),
                    "fixed_by": v["fixedBy"], "component": comp["name"],
                    "component_version": comp["version"], "purl": comp.get("purl", ""),
                    "license": comp.get("license", ""), "collected_at": ts}

        for img in data["images"]:
            deps = deps_by_img.get(img["id"]) or [None]
            for comp in img["components"]:
                for v in comp["vulns"]:
                    for d in deps:
                        row = base(v, comp)
                        row.update(asset_type="image", image=img["fullName"], image_id=img["id"])
                        if d:
                            row.update(cluster=d["clusterName"] or cl_name.get(d["clusterId"]),
                                       namespace=d["namespace"], deployment=d["name"],
                                       deployment_id=d["id"], node=";".join(d["nodes"]),
                                       exposure=d["exposure"], privileged=d["privileged"])
                        w.writerow(row)
                        rows += 1
        for n in data["nodes"]:
            for comp in n["components"]:
                for v in comp["vulns"]:
                    row = base(v, comp)
                    row.update(asset_type="node", node=n["name"],
                               cluster=n["clusterName"] or cl_name.get(n["clusterId"]))
                    w.writerow(row)
                    rows += 1
    return rows


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> None:
    ap = argparse.ArgumentParser(description="Collect asset + vulnerability inventory from RHACS Central")
    ap.add_argument("--central", default=os.getenv("ROX_CENTRAL_ADDRESS"),
                    help="Central address host[:port] or URL (env ROX_CENTRAL_ADDRESS)")
    ap.add_argument("--token-file", help="File containing the API token (else env ROX_API_TOKEN)")
    ap.add_argument("--out", default="assets.json", help="Output JSON path")
    ap.add_argument("--csv", help="Also write flat CVE x asset CSV (SIEM friendly)")
    ap.add_argument("--query", help='Optional RHACS search scope, e.g. "Cluster:prod-sg"')
    ap.add_argument("--ca-cert", help="CA bundle to verify Central's TLS certificate")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verification (lab only)")
    ap.add_argument("--timeout", type=int, default=120, help="Per-request timeout (s)")
    ap.add_argument("--page-size", type=int, default=500)
    ap.add_argument("--skip-nodes", action="store_true")
    ap.add_argument("--skip-pods", action="store_true")
    ap.add_argument("--sbom", action="store_true",
                    help="Fetch SPDX SBOMs from Central for deployed images (RHACS 4.7+ / Scanner V4)")
    ap.add_argument("--sbom-all", action="store_true", help="With --sbom: include images not currently deployed")
    ap.add_argument("--sbom-dir", help="Where raw SPDX files are stored (default: <out dir>/sbom)")
    ap.add_argument("--sbom-endpoint", default="/api/v1/images/sbom", help="Override SBOM API path if it differs")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s")
    token = (open(a.token_file).read().strip() if a.token_file else os.getenv("ROX_API_TOKEN", "").strip())
    if not a.central or not token:
        ap.error("Central address and API token are required (ROX_CENTRAL_ADDRESS / ROX_API_TOKEN)")
    if a.insecure:
        import urllib3
        urllib3.disable_warnings()
    verify: Any = False if a.insecure else (a.ca_cert or True)

    client = RhacsClient(a.central, token, verify=verify, timeout=a.timeout, page_size=a.page_size)
    sbom_dir = a.sbom_dir or os.path.join(os.path.dirname(os.path.abspath(a.out)), "sbom")
    data = collect(client, a.query, a.skip_nodes, a.skip_pods, a.sbom, a.sbom_all, sbom_dir, a.sbom_endpoint)

    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    tmp = a.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, separators=(",", ":"))
    os.replace(tmp, a.out)   # atomic swap so the webapp never reads a half-written file
    log.info("Wrote %s  %s", a.out, json.dumps(data["meta"]["counts"]))
    if a.csv:
        log.info("Wrote %s (%d rows)", a.csv, write_csv(data, a.csv))


if __name__ == "__main__":
    try:
        main()
    except requests.exceptions.SSLError as e:
        sys.exit(f"[!] TLS error talking to Central: {e}\n    Use --ca-cert <central CA> (or --insecure in a lab).")
    except requests.exceptions.ConnectionError as e:
        sys.exit(f"[!] Cannot reach Central: {e}")

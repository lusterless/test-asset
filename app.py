#!/usr/bin/env python3
"""
RHACS Asset & CVE Impact Explorer
=================================
Reads the JSON produced by collector/rhacs_collector.py, builds an in-memory
relationship graph, and serves a small web UI + JSON API for SOC analysts.

  Cluster ─┬─ Node ── (OS components ── CVEs)
           └─ Namespace ── Deployment ─┬─ Pods ── Node
                                       └─ Container ── Image ── Components ── CVEs

Run:
    pip install flask
    python app.py --data ../data/assets.json            # http://127.0.0.1:8088
    APP_USER=soc APP_PASSWORD=changeme python app.py --host 0.0.0.0

The data file is re-read automatically when the collector overwrites it.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import threading
from collections import defaultdict
from functools import wraps
from typing import Dict, List, Optional

from flask import Flask, Response, abort, jsonify, request, send_from_directory

HERE = os.path.dirname(os.path.abspath(__file__))


def _uuid_from(s: str) -> str:
    import hashlib
    import uuid
    return str(uuid.UUID(hashlib.md5(s.encode()).hexdigest()))
SEV_RANK = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1, "Unknown": 0}
EXP_RANK = {"EXTERNAL": 4, "ROUTE": 3, "NODE": 2, "HOST": 2, "INTERNAL": 1, "UNSET": 0}
CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA-[\w-]{14}|RHSA-\d{4}:\d+|ALAS\w*-\d{4}-\d+|DSA-\d+-\d+|USN-\d+-\d+)\b", re.I)


# --------------------------------------------------------------------------- #
# Inventory graph
# --------------------------------------------------------------------------- #
class Inventory:
    def __init__(self, path: str):
        self.path = path
        self.mtime = 0.0
        self.lock = threading.Lock()
        self.load()

    # ---------------------------------------------------------------- loading
    def maybe_reload(self) -> None:
        try:
            m = os.path.getmtime(self.path)
        except OSError:
            return
        if m != self.mtime:
            self.load()

    def load(self) -> None:
        with open(self.path, encoding="utf-8") as fh:
            raw = json.load(fh)
        with self.lock:
            self._index(raw)
            self.mtime = os.path.getmtime(self.path)

    def _index(self, d: dict) -> None:
        self.meta = d.get("meta", {})
        self.cves: Dict[str, dict] = d.get("cves", {})
        self.clusters = {c["id"]: c for c in d.get("clusters", [])}
        self.namespaces = {n["id"]: n for n in d.get("namespaces", []) if n.get("id")}
        self.nodes = {n["id"]: n for n in d.get("nodes", [])}
        self.deployments = {x["id"]: x for x in d.get("deployments", [])}
        self.images = {i["id"]: i for i in d.get("images", [])}

        cl_name = {c["id"]: c["name"] for c in self.clusters.values()}
        # namespace lookup by (clusterId, name) - deployments reference both
        self.ns_by_key = {(n["clusterId"], n["name"]): n for n in self.namespaces.values()}
        # node lookup by (clusterId, name) - pods reference node *names*
        self.node_by_key = {(n["clusterId"], n["name"]): n for n in self.nodes.values()}

        self.deps_by_image: Dict[str, List[str]] = defaultdict(list)
        self.deps_by_ns: Dict[str, List[str]] = defaultdict(list)
        self.deps_by_node: Dict[str, List[str]] = defaultdict(list)
        for dep in self.deployments.values():
            dep["clusterName"] = dep.get("clusterName") or cl_name.get(dep["clusterId"], "")
            ns = self.ns_by_key.get((dep["clusterId"], dep["namespace"]))
            dep["namespaceId"] = dep.get("namespaceId") or (ns["id"] if ns else "")
            if dep["namespaceId"]:
                self.deps_by_ns[dep["namespaceId"]].append(dep["id"])
            for c in dep["containers"]:
                if c.get("imageId") and dep["id"] not in self.deps_by_image[c["imageId"]]:
                    self.deps_by_image[c["imageId"]].append(dep["id"])
            dep["nodeIds"] = []
            for nn in dep.get("nodes", []):
                node = self.node_by_key.get((dep["clusterId"], nn))
                if node:
                    dep["nodeIds"].append(node["id"])
                    self.deps_by_node[node["id"]].append(dep["id"])

        # CVE -> where it lives
        self.cve_images: Dict[str, List[tuple]] = defaultdict(list)   # (imageId, comp, vuln)
        self.cve_nodes: Dict[str, List[tuple]] = defaultdict(list)    # (nodeId, comp, vuln)
        for img in self.images.values():
            img_cves, fixable, top = set(), set(), 0.0
            for comp in img.get("components", []):
                for v in comp.get("vulns", []):
                    self.cve_images[v["cve"]].append((img["id"], comp, v))
                    img_cves.add(v["cve"])
                    if v.get("fixedBy"):
                        fixable.add(v["cve"])
                    top = max(top, self.cves.get(v["cve"], {}).get("cvss") or 0)
            img["cveCount"] = len(img_cves)
            img["fixableCount"] = len(fixable)
            img["topCvss"] = top
            img["sevCounts"] = self._sev_counts(img_cves)
            img["deploymentCount"] = len(self.deps_by_image.get(img["id"], []))
        for node in self.nodes.values():
            node["clusterName"] = node.get("clusterName") or cl_name.get(node["clusterId"], "")
            ncves = set()
            for comp in node.get("components", []):
                for v in comp.get("vulns", []):
                    self.cve_nodes[v["cve"]].append((node["id"], comp, v))
                    ncves.add(v["cve"])
            node["cveCount"] = len(ncves)
            node["sevCounts"] = self._sev_counts(ncves)
            node["deploymentCount"] = len(self.deps_by_node.get(node["id"], []))

        # package (SBOM) index: name -> version -> where used + package metadata
        self.pkg_index: Dict[str, Dict[str, dict]] = defaultdict(dict)

        def pk(comp):
            e = self.pkg_index[comp["name"]].get(comp["version"])
            if e is None:
                e = self.pkg_index[comp["name"]][comp["version"]] = {
                    "images": set(), "nodes": set(), "purls": set(), "licenses": set(), "suppliers": set(),
                    "sources": set(), "locations": set(), "cpes": set(), "cves": {}}
            for key, field in (("purls", "purl"), ("licenses", "license"), ("suppliers", "supplier"),
                               ("sources", "source"), ("locations", "location"), ("cpes", "cpe")):
                if comp.get(field):
                    e[key].add(comp[field])
            for v in comp.get("vulns", []):
                e["cves"].setdefault(v["cve"], v.get("fixedBy") or "")
            return e

        for img in self.images.values():
            for comp in img.get("components", []):
                pk(comp)["images"].add(img["id"])
        for node in self.nodes.values():
            for comp in node.get("components", []):
                pk(comp)["nodes"].add(node["id"])

        # roll image CVEs up to deployments
        for dep in self.deployments.values():
            cves = set()
            for c in dep["containers"]:
                img = self.images.get(c.get("imageId"))
                if img:
                    for comp in img["components"]:
                        cves.update(v["cve"] for v in comp["vulns"])
            dep["cveCount"] = len(cves)
            dep["sevCounts"] = self._sev_counts(cves)

        # CVE impact rollups (for catalog sorting)
        for cid, c in self.cves.items():
            imgs = {i for i, _, _ in self.cve_images.get(cid, [])}
            deps = {dp for i in imgs for dp in self.deps_by_image.get(i, [])}
            c["imageCount"] = len(imgs)
            c["deploymentCount"] = len(deps)
            c["nodeCount"] = len({n for n, _, _ in self.cve_nodes.get(cid, [])})
            c["fixable"] = any(v.get("fixedBy") for _, _, v in self.cve_images.get(cid, []) + self.cve_nodes.get(cid, []))
            c["clusterCount"] = len({self.deployments[x]["clusterId"] for x in deps} |
                                    {self.nodes[n]["clusterId"] for n, _, _ in self.cve_nodes.get(cid, [])})

    def _sev_counts(self, cve_ids) -> dict:
        out = {"Critical": 0, "Important": 0, "Moderate": 0, "Low": 0}
        for c in cve_ids:
            s = self.cves.get(c, {}).get("severity", "Unknown")
            if s in out:
                out[s] += 1
        return out

    # ------------------------------------------------------------ summaries
    def dep_brief(self, dep: dict) -> dict:
        return {k: dep.get(k) for k in ("id", "name", "type", "namespace", "namespaceId", "clusterId",
                                         "clusterName", "riskScore", "exposure", "privileged",
                                         "hostNetwork", "inactive", "cveCount", "sevCounts", "podCount")}

    def img_brief(self, img: dict) -> dict:
        return {k: img.get(k) for k in ("id", "fullName", "os", "scanTime", "cveCount", "fixableCount",
                                         "topCvss", "sevCounts", "deploymentCount", "notes")}

    def node_brief(self, n: dict) -> dict:
        return {k: n.get(k) for k in ("id", "name", "clusterId", "clusterName", "os", "kernel",
                                       "runtime", "kubelet", "internalIps", "cveCount", "sevCounts",
                                       "deploymentCount")}

    # ------------------------------------------------------------- summary
    def summary(self) -> dict:
        sev = defaultdict(int)
        for c in self.cves.values():
            sev[c["severity"]] += 1
        top_cves = sorted(
            (dict(id=k, **{x: v.get(x) for x in ("severity", "cvss", "epssProbability", "deploymentCount",
                                                  "imageCount", "nodeCount", "fixable", "summary")})
             for k, v in self.cves.items() if v["deploymentCount"] or v["nodeCount"]),
            key=lambda c: (SEV_RANK.get(c["severity"], 0), c["deploymentCount"] + c["nodeCount"], c["cvss"] or 0),
            reverse=True)[:15]
        top_deps = sorted(self.deployments.values(),
                          key=lambda d: (d["sevCounts"]["Critical"], d["sevCounts"]["Important"], d.get("riskScore") or 0),
                          reverse=True)[:10]
        exposed_crit = [d for d in self.deployments.values()
                        if d["sevCounts"]["Critical"] and EXP_RANK.get(d.get("exposure"), 0) >= 3]
        return {
            "meta": self.meta,
            "counts": {"clusters": len(self.clusters), "namespaces": len(self.namespaces),
                       "nodes": len(self.nodes), "deployments": len(self.deployments),
                       "images": len(self.images), "cves": len(self.cves)},
            "severity": sev,
            "topCves": top_cves,
            "topDeployments": [self.dep_brief(d) for d in top_deps],
            "exposedCritical": [self.dep_brief(d) for d in exposed_crit][:20],
            "clusters": [dict(c, deploymentCount=sum(1 for d in self.deployments.values() if d["clusterId"] == c["id"]),
                              nodeCount=sum(1 for n in self.nodes.values() if n["clusterId"] == c["id"]))
                         for c in self.clusters.values()],
        }

    # ---------------------------------------------------------- CVE impact
    def resolve_cve(self, q: str) -> List[str]:
        """Exact id, else match on advisory name (e.g. RHSA) or case-insensitive id."""
        q = q.strip()
        if q in self.cves:
            return [q]
        up = q.upper()
        hits = [k for k, v in self.cves.items() if k.upper() == up or (v.get("advisory") or "").upper() == up]
        return hits

    def cve_impact(self, cve_id: str) -> dict:
        info = self.cves.get(cve_id)
        if not info:
            return {"id": cve_id, "found": False}
        rows, images, deps, nss, cls = [], {}, {}, set(), set()
        for img_id, comp, v in self.cve_images.get(cve_id, []):
            img = self.images[img_id]
            images[img_id] = dict(self.img_brief(img), component=comp["name"], version=comp["version"],
                                  fixedBy=v.get("fixedBy"), source=comp.get("source"), location=comp.get("location"))
            for dep_id in self.deps_by_image.get(img_id, []) or [None]:
                dep = self.deployments.get(dep_id) if dep_id else None
                if dep:
                    deps[dep_id] = dep
                    nss.add((dep["clusterId"], dep["namespace"]))
                    cls.add(dep["clusterId"])
                rows.append({
                    "assetType": "image",
                    "cluster": dep["clusterName"] if dep else "", "clusterId": dep["clusterId"] if dep else "",
                    "namespace": dep["namespace"] if dep else "", "namespaceId": dep["namespaceId"] if dep else "",
                    "deployment": dep["name"] if dep else "(not deployed)", "deploymentId": dep_id or "",
                    "exposure": dep["exposure"] if dep else "", "privileged": dep["privileged"] if dep else None,
                    "riskScore": dep.get("riskScore") if dep else None,
                    "nodes": [{"id": nid, "name": self.nodes[nid]["name"]} for nid in (dep or {}).get("nodeIds", [])],
                    "image": img["fullName"], "imageId": img_id,
                    "component": comp["name"], "version": comp["version"], "fixedBy": v.get("fixedBy") or "",
                })
        node_rows = []
        for node_id, comp, v in self.cve_nodes.get(cve_id, []):
            n = self.nodes[node_id]
            cls.add(n["clusterId"])
            node_rows.append(dict(self.node_brief(n), component=comp["name"], version=comp["version"],
                                  fixedBy=v.get("fixedBy") or ""))
        rows.sort(key=lambda r: (-EXP_RANK.get(r["exposure"], 0), -(r["riskScore"] or 0), r["cluster"], r["namespace"]))
        return {
            "id": cve_id, "found": True, "info": info,
            "blast": {"clusters": len(cls), "namespaces": len(nss), "deployments": len(deps),
                      "images": len(images), "nodes": len(node_rows),
                      "exposed": sum(1 for d in deps.values() if EXP_RANK.get(d["exposure"], 0) >= 3),
                      "privileged": sum(1 for d in deps.values() if d["privileged"])},
            "workloads": rows,
            "images": sorted(images.values(), key=lambda i: -i["deploymentCount"]),
            "nodes": node_rows,
            "clusters": [{"id": c, "name": self.clusters.get(c, {}).get("name", c)} for c in cls],
        }

    # ------------------------------------------------------ package hunting
    def component_hunt(self, name: str, version: str = "", exact: bool = False) -> dict:
        name_l, ver = name.lower().strip(), version.strip()
        match = (lambda n: n.lower() == name_l) if exact else (lambda n: name_l in n.lower())
        out_imgs, out_nodes = [], []
        for img in self.images.values():
            for comp in img["components"]:
                if match(comp["name"]) and (not ver or comp["version"].startswith(ver)):
                    deps = [self.dep_brief(self.deployments[x]) for x in self.deps_by_image.get(img["id"], [])]
                    out_imgs.append({"imageId": img["id"], "image": img["fullName"], "component": comp["name"],
                                     "version": comp["version"], "source": comp.get("source"),
                                     "location": comp.get("location"), "cves": [v["cve"] for v in comp["vulns"]],
                                     "purl": comp.get("purl", ""), "license": comp.get("license", ""),
                                     "deployments": deps})
        for n in self.nodes.values():
            for comp in n["components"]:
                if match(comp["name"]) and (not ver or comp["version"].startswith(ver)):
                    out_nodes.append(dict(self.node_brief(n), component=comp["name"], version=comp["version"],
                                          cves=[v["cve"] for v in comp["vulns"]]))
        versions = defaultdict(int)
        for r in out_imgs + out_nodes:
            versions[f'{r["component"]} {r["version"]}'] += 1
        return {"query": {"name": name, "version": version, "exact": exact},
                "images": out_imgs[:2000], "nodes": out_nodes[:2000],
                "versions": sorted(versions.items(), key=lambda kv: -kv[1])[:50],
                "deploymentCount": len({d["id"] for r in out_imgs for d in r["deployments"]})}

    # -------------------------------------------------------------- search
    def search(self, q: str, limit: int = 25) -> dict:
        ql = q.lower().strip()
        if not ql:
            return {}
        res = {"cves": [], "deployments": [], "images": [], "namespaces": [], "nodes": [], "clusters": [], "components": []}
        ids = {m.upper() for m in CVE_RE.findall(q)}
        for k, v in self.cves.items():
            if k.upper() in ids or ql in k.lower() or (v.get("advisory") or "").lower() == ql:
                res["cves"].append({"id": k, "severity": v["severity"], "cvss": v["cvss"],
                                    "deploymentCount": v["deploymentCount"], "nodeCount": v["nodeCount"]})
        res["cves"] = sorted(res["cves"], key=lambda c: -(c["deploymentCount"] + c["nodeCount"]))[:limit]
        res["deployments"] = [self.dep_brief(d) for d in self.deployments.values()
                              if ql in d["name"].lower() or ql in f'{d["namespace"]}/{d["name"]}'.lower()][:limit]
        res["images"] = [self.img_brief(i) for i in self.images.values()
                         if any(ql in n.lower() for n in i["names"]) or ql in i["id"].lower()][:limit]
        res["namespaces"] = [n for n in self.namespaces.values() if ql in n["name"].lower()][:limit]
        res["nodes"] = [self.node_brief(n) for n in self.nodes.values()
                        if ql in n["name"].lower() or any(ql == ip for ip in n["internalIps"] + n["externalIps"])][:limit]
        res["clusters"] = [c for c in self.clusters.values() if ql in c["name"].lower()][:limit]
        comps = defaultdict(set)
        for img in self.images.values():
            for c in img["components"]:
                if ql in c["name"].lower():
                    comps[c["name"]].add(img["id"])
        res["components"] = sorted(({"name": k, "imageCount": len(v)} for k, v in comps.items()),
                                   key=lambda c: -c["imageCount"])[:limit]
        return res

    # ------------------------------------------------------------- details
    def cluster_detail(self, cid: str) -> Optional[dict]:
        c = self.clusters.get(cid)
        if not c:
            return None
        nss = [dict(n, deploymentCount=len(self.deps_by_ns.get(n["id"], [])),
                    cveCritical=sum(self.deployments[d]["sevCounts"]["Critical"] for d in self.deps_by_ns.get(n["id"], [])))
               for n in self.namespaces.values() if n["clusterId"] == cid]
        return {"cluster": c,
                "namespaces": sorted(nss, key=lambda n: -n["cveCritical"]),
                "nodes": [self.node_brief(n) for n in self.nodes.values() if n["clusterId"] == cid]}

    def namespace_detail(self, nid: str) -> Optional[dict]:
        n = self.namespaces.get(nid)
        if not n:
            return None
        deps = [self.dep_brief(self.deployments[d]) for d in self.deps_by_ns.get(nid, [])]
        return {"namespace": n, "deployments": sorted(deps, key=lambda d: -(d.get("riskScore") or 0))}

    def deployment_detail(self, did: str) -> Optional[dict]:
        d = self.deployments.get(did)
        if not d:
            return None
        containers = []
        for c in d["containers"]:
            img = self.images.get(c.get("imageId"))
            containers.append(dict(c, imageInfo=self.img_brief(img) if img else None))
        return {"deployment": d, "containers": containers,
                "nodes": [self.node_brief(self.nodes[x]) for x in d.get("nodeIds", [])],
                "cves": self._cve_rows_for_images([c["imageId"] for c in d["containers"] if c.get("imageId")])}

    def image_detail(self, iid: str) -> Optional[dict]:
        img = self.images.get(iid)
        if not img:
            return None
        return {"image": {k: v for k, v in img.items() if k != "components"},
                "components": [{"name": c["name"], "version": c["version"], "source": c.get("source"),
                                "location": c.get("location"), "cveCount": len(c["vulns"]),
                                "purl": c.get("purl", ""), "purlSource": c.get("purlSource", ""),
                                "license": c.get("license", ""), "supplier": c.get("supplier", ""),
                                "worst": self._worst(v["cve"] for v in c["vulns"])} for c in img["components"]],
                "deployments": [self.dep_brief(self.deployments[x]) for x in self.deps_by_image.get(iid, [])],
                "cves": self._cve_rows_for_images([iid])}

    def node_detail(self, nid: str) -> Optional[dict]:
        n = self.nodes.get(nid)
        if not n:
            return None
        rows = []
        for comp in n["components"]:
            for v in comp["vulns"]:
                c = self.cves.get(v["cve"], {})
                rows.append({"cve": v["cve"], "severity": c.get("severity"), "cvss": c.get("cvss"),
                             "component": comp["name"], "version": comp["version"], "fixedBy": v.get("fixedBy")})
        rows.sort(key=lambda r: (-SEV_RANK.get(r["severity"], 0), -(r["cvss"] or 0)))
        return {"node": {k: v for k, v in n.items() if k != "components"},
                "deployments": [self.dep_brief(self.deployments[x]) for x in self.deps_by_node.get(nid, [])],
                "cves": rows}

    def _cve_rows_for_images(self, image_ids) -> List[dict]:
        rows, seen = [], set()
        for iid in image_ids:
            img = self.images.get(iid)
            if not img:
                continue
            for comp in img["components"]:
                for v in comp["vulns"]:
                    key = (v["cve"], comp["name"], comp["version"], iid)
                    if key in seen:
                        continue
                    seen.add(key)
                    c = self.cves.get(v["cve"], {})
                    rows.append({"cve": v["cve"], "severity": c.get("severity"), "cvss": c.get("cvss"),
                                 "epss": c.get("epssProbability"), "component": comp["name"],
                                 "version": comp["version"], "fixedBy": v.get("fixedBy"),
                                 "image": img["fullName"], "imageId": iid})
        rows.sort(key=lambda r: (-SEV_RANK.get(r["severity"], 0), -(r["cvss"] or 0)))
        return rows

    # ------------------------------------------------------------- SBOM / packages
    def _worst(self, cve_ids) -> str:
        best = "None"
        for c in cve_ids:
            s = self.cves.get(c, {}).get("severity", "Unknown")
            if best == "None" or SEV_RANK.get(s, 0) > SEV_RANK.get(best, -1):
                best = s
        return best

    def packages(self, q: str = "", limit: int = 50) -> List[dict]:
        ql = q.lower().strip()
        out = []
        for name, vers in self.pkg_index.items():
            if ql and ql not in name.lower():
                continue
            imgs = set().union(*(v["images"] for v in vers.values()))
            nodes = set().union(*(v["nodes"] for v in vers.values()))
            cves = set().union(*(v["cves"].keys() for v in vers.values()))
            out.append({"name": name, "versions": len(vers), "images": len(imgs), "nodes": len(nodes),
                        "deployments": len({d for i in imgs for d in self.deps_by_image.get(i, [])}),
                        "cves": len(cves), "worst": self._worst(cves),
                        "types": sorted(set().union(*(v["sources"] for v in vers.values())))})
        # exact match first, then by footprint
        out.sort(key=lambda p: (p["name"].lower() != ql, -(p["images"] + p["nodes"]), p["name"]))
        return out[:limit]

    def _pkg_info(self, name: str, version: str, e: dict) -> dict:
        cves = [{"cve": c, "fixedBy": fb, "severity": self.cves.get(c, {}).get("severity"),
                 "cvss": self.cves.get(c, {}).get("cvss"), "epss": self.cves.get(c, {}).get("epssProbability")}
                for c, fb in e["cves"].items()]
        cves.sort(key=lambda r: (-SEV_RANK.get(r["severity"], 0), -(r["cvss"] or 0)))
        return {"name": name, "version": version, "purls": sorted(e["purls"]), "licenses": sorted(e["licenses"]),
                "suppliers": sorted(e["suppliers"]), "types": sorted(e["sources"]), "cpes": sorted(e["cpes"]),
                "locations": sorted(e["locations"])[:20], "imageCount": len(e["images"]), "nodeCount": len(e["nodes"]),
                "cves": cves, "worst": self._worst(e["cves"]), "fixable": any(fb for fb in e["cves"].values())}

    def package_graph(self, name: str, version: str = "", exact: bool = False, vuln_only: bool = False,
                      max_nodes: int = 600) -> dict:
        """Layered graph: package@version -> image|host -> deployment -> namespace -> cluster."""
        ql = name.lower().strip()
        nodes: Dict[str, dict] = {}
        edges = set()
        truncated = False

        def add(nid, col, ntype, label, sub="", sev=None, info=None, link=None):
            nonlocal truncated
            if nid in nodes:
                return True
            if len(nodes) >= max_nodes:
                truncated = True
                return False
            nodes[nid] = {"id": nid, "col": col, "type": ntype, "label": label, "sub": sub,
                          "sev": sev, "info": info or {}, "link": link}
            return True

        pkgs = []
        for pname, vers in self.pkg_index.items():
            if (pname.lower() != ql) if exact else (ql not in pname.lower()):
                continue
            for ver, e in vers.items():
                if version and not ver.startswith(version):
                    continue
                if vuln_only and not e["cves"]:
                    continue
                pkgs.append((pname, ver, e))
        pkgs.sort(key=lambda t: (t[0], t[1]))

        for pname, ver, e in pkgs:
            info = self._pkg_info(pname, ver, e)
            pid = f"p:{pname}@{ver}"
            if not add(pid, 0, "package", f"{pname} {ver}", ", ".join(info["types"]) or "package",
                       info["worst"], info, f"#/package?name={pname}&version={ver}&exact=1"):
                break
            for iid in e["images"]:
                img = self.images[iid]
                iid_n = f"i:{iid}"
                if add(iid_n, 1, "image", img["fullName"].split("/")[-1], img["fullName"],
                       self._worst_sev(img["sevCounts"]),
                       {**self.img_brief(img), "sbom": img.get("sbom", {})}, f"#/image/{iid}"):
                    edges.add((pid, iid_n))
                for did in self.deps_by_image.get(iid, []):
                    d = self.deployments[did]
                    did_n = f"d:{did}"
                    if not add(did_n, 2, "deployment", d["name"], f'{d["type"]} · {d["exposure"]}',
                               self._worst_sev(d["sevCounts"]), self.dep_brief(d), f"#/deployment/{did}"):
                        continue
                    edges.add((iid_n, did_n))
                    ns_key = d["namespaceId"] or f'{d["clusterId"]}/{d["namespace"]}'
                    ns_n = f"n:{ns_key}"
                    add(ns_n, 3, "namespace", d["namespace"], d["clusterName"], None,
                        {"name": d["namespace"], "cluster": d["clusterName"]},
                        f"#/namespace/{d['namespaceId']}" if d["namespaceId"] else None)
                    edges.add((did_n, ns_n))
                    c_n = f"c:{d['clusterId']}"
                    c = self.clusters.get(d["clusterId"], {})
                    add(c_n, 4, "cluster", c.get("name", d["clusterName"]), c.get("type", ""), None, c,
                        f"#/cluster/{d['clusterId']}")
                    edges.add((ns_n, c_n))
            for nid in e["nodes"]:
                n = self.nodes[nid]
                h_n = f"h:{nid}"
                if add(h_n, 1, "host", n["name"], f'node · {(n.get("internalIps") or [""])[0]}',
                       self._worst_sev(n["sevCounts"]), self.node_brief(n), f"#/node/{nid}"):
                    edges.add((pid, h_n))
                    c_n = f"c:{n['clusterId']}"
                    c = self.clusters.get(n["clusterId"], {})
                    add(c_n, 4, "cluster", c.get("name", n["clusterName"]), c.get("type", ""), None, c,
                        f"#/cluster/{n['clusterId']}")
                    edges.add((h_n, c_n))

        e_list = [{"s": s, "t": t} for s, t in edges if s in nodes and t in nodes]
        cols = defaultdict(int)
        for n in nodes.values():
            cols[n["type"]] += 1
        return {"query": {"name": name, "version": version, "exact": exact, "vulnOnly": vuln_only},
                "nodes": list(nodes.values()), "edges": e_list, "counts": dict(cols), "truncated": truncated,
                "packages": [self._pkg_info(p, v, e) for p, v, e in pkgs][:200]}

    @staticmethod
    def _worst_sev(c: dict):
        for s in ("Critical", "Important", "Moderate", "Low"):
            if c and c.get(s):
                return s
        return "None"

    def image_sbom(self, iid: str, fmt: str, sbom_dir: str):
        """Return (doc, filename). Official RHACS SPDX if collected, otherwise generated from scan data."""
        img = self.images.get(iid)
        if not img:
            return None, None
        safe = re.sub(r"[^a-zA-Z0-9]", "", iid.replace("sha256:", ""))[:80]
        base = re.sub(r"[^\w.-]+", "_", img["fullName"])[:120] or safe
        sb = img.get("sbom") or {}
        if fmt == "spdx" and sb.get("available") and sb.get("file"):
            path = os.path.join(sbom_dir, safe + ".spdx.json")
            if os.path.isfile(path):
                with open(path, encoding="utf-8") as fh:
                    return json.load(fh), f"{base}.spdx.json"
        created = self.meta.get("collectedAt") or ""
        comps = img.get("components", [])
        if fmt == "cyclonedx":
            vulns = defaultdict(list)
            for i, c in enumerate(comps):
                for v in c["vulns"]:
                    vulns[v["cve"]].append((f"comp-{i}", v.get("fixedBy")))
            doc = {
                "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                "serialNumber": "urn:uuid:" + _uuid_from(iid + created),
                "metadata": {"timestamp": created, "tools": [{"vendor": "rhacs-asset-inventory", "name": "webapp"}],
                             "component": {"type": "container", "name": img["fullName"], "version": iid,
                                           "bom-ref": "image"}},
                "components": [{"type": "library", "bom-ref": f"comp-{i}", "name": c["name"], "version": c["version"],
                                **({"purl": c["purl"]} if c.get("purl") else {}),
                                **({"licenses": [{"license": {"name": c["license"]}}]} if c.get("license") else {}),
                                **({"supplier": {"name": c["supplier"]}} if c.get("supplier") else {}),
                                "properties": [{"name": "rhacs:source", "value": c.get("source") or ""},
                                               {"name": "rhacs:location", "value": c.get("location") or ""}]}
                               for i, c in enumerate(comps)],
                "vulnerabilities": [{"id": cve, "source": {"name": "RHACS", "url": self.cves.get(cve, {}).get("link", "")},
                                     "ratings": [{"score": self.cves.get(cve, {}).get("cvss"),
                                                  "severity": (self.cves.get(cve, {}).get("severity") or "unknown").lower()
                                                  .replace("important", "high").replace("moderate", "medium")}],
                                     "affects": [{"ref": ref} for ref, _ in refs],
                                     "recommendation": "; ".join(sorted({f"upgrade to {fb}" for _, fb in refs if fb}))}
                                    for cve, refs in vulns.items()],
            }
            return doc, f"{base}.cdx.json"
        pkgs = [{"SPDXID": "SPDXRef-image", "name": img["fullName"], "versionInfo": iid,
                 "downloadLocation": "NOASSERTION", "primaryPackagePurpose": "CONTAINER", "filesAnalyzed": False}]
        rels = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-image"}]
        for i, c in enumerate(comps):
            sid = f"SPDXRef-Package-{i}"
            p = {"SPDXID": sid, "name": c["name"], "versionInfo": c["version"], "downloadLocation": "NOASSERTION",
                 "filesAnalyzed": False, "licenseConcluded": c.get("license") or "NOASSERTION",
                 "supplier": f"Organization: {c['supplier']}" if c.get("supplier") else "NOASSERTION"}
            if c.get("purl"):
                p["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                      "referenceLocator": c["purl"]}]
            if c.get("location"):
                p["comment"] = f"location: {c['location']}"
            pkgs.append(p)
            rels.append({"spdxElementId": "SPDXRef-image", "relationshipType": "CONTAINS", "relatedSpdxElement": sid})
        doc = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
               "name": img["fullName"], "documentNamespace": f"https://rhacs-asset-inventory/spdx/{safe}",
               "creationInfo": {"created": created or "1970-01-01T00:00:00Z",
                                "creators": ["Tool: rhacs-asset-inventory (derived from RHACS scan data)"]},
               "packages": pkgs, "relationships": rels}
        return doc, f"{base}.spdx.json"

    def cve_catalog(self, severity: str = "", fixable: str = "", q: str = "", deployed_only: bool = True,
                    limit: int = 500) -> List[dict]:
        out = []
        for k, v in self.cves.items():
            if severity and v["severity"] != severity:
                continue
            if fixable == "yes" and not v["fixable"]:
                continue
            if fixable == "no" and v["fixable"]:
                continue
            if deployed_only and not (v["deploymentCount"] or v["nodeCount"]):
                continue
            if q and q.lower() not in k.lower() and q.lower() not in (v.get("summary") or "").lower():
                continue
            out.append(dict(id=k, **{x: v.get(x) for x in ("severity", "cvss", "epssProbability", "publishedOn",
                                                           "fixable", "deploymentCount", "imageCount", "nodeCount",
                                                           "clusterCount", "summary")}))
        out.sort(key=lambda c: (SEV_RANK.get(c["severity"], 0), c["deploymentCount"] + c["nodeCount"], c["cvss"] or 0),
                 reverse=True)
        return out[:limit]


# --------------------------------------------------------------------------- #
# Flask app
# --------------------------------------------------------------------------- #
def create_app(data_path: str) -> Flask:
    app = Flask(__name__, static_folder=os.path.join(HERE, "static"), static_url_path="/static")
    inv = Inventory(data_path)
    user, pwd = os.getenv("APP_USER"), os.getenv("APP_PASSWORD")

    def guarded(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if user and pwd:
                auth = request.authorization
                if not auth or auth.username != user or auth.password != pwd:
                    return Response("Authentication required", 401,
                                    {"WWW-Authenticate": 'Basic realm="RHACS Asset Explorer"'})
            inv.maybe_reload()
            return fn(*a, **kw)
        return wrapper

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:")
        return resp

    @app.get("/")
    @guarded
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.get("/api/summary")
    @guarded
    def api_summary():
        return jsonify(inv.summary())

    @app.get("/api/impact")
    @guarded
    def api_impact():
        raw = request.args.get("ids", "")
        tokens = [t for t in re.split(r"[\s,;]+", raw) if t][:100]
        results, missing = [], []
        for t in tokens:
            ids = inv.resolve_cve(t)
            if not ids:
                missing.append(t)
            for cid in ids:
                results.append(inv.cve_impact(cid))
        return jsonify({"results": results, "notFound": missing})

    @app.get("/api/impact.csv")
    @guarded
    def api_impact_csv():
        tokens = [t for t in re.split(r"[\s,;]+", request.args.get("ids", "")) if t][:100]
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["cve", "severity", "cvss", "asset_type", "cluster", "namespace", "deployment", "exposure",
                    "privileged", "nodes", "image", "component", "version", "fixed_by"])
        for t in tokens:
            for cid in inv.resolve_cve(t):
                r = inv.cve_impact(cid)
                info = r.get("info", {})
                for x in r.get("workloads", []):
                    w.writerow([cid, info.get("severity"), info.get("cvss"), "workload", x["cluster"], x["namespace"],
                                x["deployment"], x["exposure"], x["privileged"], ";".join(n["name"] for n in x["nodes"]),
                                x["image"], x["component"], x["version"], x["fixedBy"]])
                for n in r.get("nodes", []):
                    w.writerow([cid, info.get("severity"), info.get("cvss"), "node", n["clusterName"], "", "", "", "",
                                n["name"], "", n["component"], n["version"], n["fixedBy"]])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=cve_impact.csv"})

    @app.get("/api/component")
    @guarded
    def api_component():
        name = request.args.get("name", "").strip()
        if len(name) < 2:
            abort(400, "name must be at least 2 characters")
        return jsonify(inv.component_hunt(name, request.args.get("version", ""), request.args.get("exact") == "1"))

    @app.get("/api/search")
    @guarded
    def api_search():
        return jsonify(inv.search(request.args.get("q", "")))

    @app.get("/api/cves")
    @guarded
    def api_cves():
        a = request.args
        return jsonify(inv.cve_catalog(a.get("severity", ""), a.get("fixable", ""), a.get("q", ""),
                                       a.get("all") != "1", int(a.get("limit", 500))))

    @app.get("/api/clusters")
    @guarded
    def api_clusters():
        return jsonify(inv.summary()["clusters"])

    @app.get("/api/images")
    @guarded
    def api_images():
        imgs = sorted(inv.images.values(), key=lambda i: (i["sevCounts"]["Critical"], i["cveCount"]), reverse=True)
        return jsonify([inv.img_brief(i) for i in imgs][:1000])

    @app.get("/api/nodes")
    @guarded
    def api_nodes():
        return jsonify([inv.node_brief(n) for n in sorted(inv.nodes.values(), key=lambda n: -n["cveCount"])])

    @app.get("/api/packages")
    @guarded
    def api_packages():
        return jsonify(inv.packages(request.args.get("q", ""), int(request.args.get("limit", 50))))

    @app.get("/api/package-graph")
    @guarded
    def api_package_graph():
        name = request.args.get("name", "").strip()
        if len(name) < 2:
            abort(400, "name must be at least 2 characters")
        a = request.args
        return jsonify(inv.package_graph(name, a.get("version", "").strip(), a.get("exact") == "1",
                                         a.get("vuln") == "1"))

    @app.get("/api/sbom/<path:iid>")
    @guarded
    def api_sbom(iid):
        fmt = request.args.get("format", "spdx")
        if fmt not in ("spdx", "cyclonedx"):
            abort(400, "format must be spdx or cyclonedx")
        sbom_dir = inv.meta.get("sbomDir") or ""
        if not os.path.isdir(sbom_dir):
            sbom_dir = os.path.join(os.path.dirname(os.path.abspath(data_path)), "sbom")
        doc, fname = inv.image_sbom(iid, fmt, sbom_dir)
        if doc is None:
            abort(404)
        return Response(json.dumps(doc, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{fname}"'})

    detail = {"cluster": inv.cluster_detail, "namespace": inv.namespace_detail,
              "deployment": inv.deployment_detail, "image": inv.image_detail, "node": inv.node_detail}

    @app.get("/api/<kind>/<path:obj_id>")
    @guarded
    def api_detail(kind, obj_id):
        fn = detail.get(kind)
        if not fn:
            abort(404)
        res = fn(obj_id)
        if res is None:
            abort(404)
        return jsonify(res)

    return app


def main():
    ap = argparse.ArgumentParser(description="RHACS asset & CVE impact explorer")
    ap.add_argument("--data", default=os.path.join(HERE, "..", "data", "assets.json"))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8088)
    a = ap.parse_args()
    if a.host not in ("127.0.0.1", "localhost") and not os.getenv("APP_PASSWORD"):
        print("[!] WARNING: listening on a non-local interface without APP_USER/APP_PASSWORD set.")
    create_app(a.data).run(host=a.host, port=a.port, threaded=True)


if __name__ == "__main__":
    main()

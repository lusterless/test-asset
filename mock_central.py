#!/usr/bin/env python3
"""
Mock RHACS Central API - serves realistic, randomly generated data in the
same shape as the real API so you can test the collector + webapp offline.

    pip install flask
    python tools/mock_central.py --port 8443            # http://127.0.0.1:8443
    ROX_API_TOKEN=dummy python collector/rhacs_collector.py \
        --central http://127.0.0.1:8443 --out data/assets.json

Implements: /v1/clusters, /v1/namespaces, /v1/export/{deployments,images,nodes,pods}
"""
import argparse
import hashlib
import json
import random

from flask import Flask, Response, jsonify, request

R = random.Random(42)
SEV = ["CRITICAL_VULNERABILITY_SEVERITY", "IMPORTANT_VULNERABILITY_SEVERITY",
       "MODERATE_VULNERABILITY_SEVERITY", "LOW_VULNERABILITY_SEVERITY"]

# A few famous CVEs so demos are meaningful
FAMOUS = [
    ("CVE-2024-3094", "xz", "5.6.0", "5.6.1-r2", 10.0, 0, "Malicious backdoor in xz/liblzma 5.6.0-5.6.1 allows SSH auth bypass.", "OS"),
    ("CVE-2021-44228", "log4j-core", "2.14.1", "2.17.1", 10.0, 0, "Log4Shell: JNDI lookup RCE in Apache Log4j2.", "JAVA"),
    ("CVE-2023-44487", "golang.org/x/net", "v0.15.0", "v0.17.0", 7.5, 1, "HTTP/2 Rapid Reset DoS.", "GO"),
    ("CVE-2024-6387", "openssh", "9.6p1", "9.8p1", 8.1, 1, "regreSSHion: signal handler race in sshd allows RCE.", "OS"),
    ("CVE-2022-3602", "openssl", "3.0.6", "3.0.7", 7.5, 1, "X.509 email address 4-byte buffer overflow.", "OS"),
    ("CVE-2023-4911", "glibc", "2.34", "2.34-60", 7.8, 1, "Looney Tunables: buffer overflow in ld.so GLIBC_TUNABLES.", "OS"),
]
COMMON_PKGS = [("openssl", "3.0.7"), ("glibc", "2.34"), ("zlib", "1.2.13"), ("curl", "7.76.1"), ("bash", "5.1.8"),
               ("libxml2", "2.9.13"), ("python3", "3.9.18"), ("ncurses", "6.2"), ("sqlite", "3.34.1"),
               ("nghttp2", "1.43.0"), ("expat", "2.5.0"), ("krb5-libs", "1.21.1"), ("systemd-libs", "252")]


def sha(s):
    return "sha256:" + hashlib.sha256(s.encode()).hexdigest()


def vuln(cve, sev, cvss, summary, fixed):
    return {"cve": cve, "cvss": cvss, "severity": sev, "summary": summary, "fixedBy": fixed,
            "link": f"https://access.redhat.com/security/cve/{cve}", "publishedOn": f"20{R.randint(21,26)}-0{R.randint(1,9)}-1{R.randint(0,9)}T00:00:00Z",
            "scoreVersion": "V3", "epss": {"epssProbability": round(R.random() ** 3, 4), "epssPercentile": round(R.random(), 3)},
            "vulnerabilityType": "IMAGE_VULNERABILITY", "state": "OBSERVED"}


def rand_vulns(n):
    out = []
    for _ in range(n):
        cvss = round(R.uniform(2, 9.8), 1)
        sev = SEV[0] if cvss >= 9 else SEV[1] if cvss >= 7 else SEV[2] if cvss >= 4 else SEV[3]
        out.append(vuln(f"CVE-20{R.randint(19,26)}-{R.randint(1000,49999)}", sev, cvss,
                        "Synthetic vulnerability for testing.", R.choice(["", "", f"{R.randint(1,9)}.{R.randint(0,9)}.{R.randint(0,30)}"])))
    return out


def build():
    clusters = [
        {"id": "c-sg-prod", "name": "sg-gpu-prod", "type": "OPENSHIFT4_CLUSTER",
         "status": {"sensorVersion": "4.8.2", "orchestratorMetadata": {"version": "v1.30.6", "openshiftVersion": "4.17.12"},
                    "providerMetadata": {"region": "ap-southeast-1"}},
         "healthStatus": {"overallHealthStatus": "HEALTHY"}},
        {"id": "c-sg-stg", "name": "sg-staging", "type": "KUBERNETES_CLUSTER",
         "status": {"sensorVersion": "4.8.2", "orchestratorMetadata": {"version": "v1.29.4"},
                    "providerMetadata": {"region": "ap-southeast-1"}},
         "healthStatus": {"overallHealthStatus": "DEGRADED"}},
    ]
    ns_names = ["ai-inference", "training-jobs", "jupyter-hub", "api-gateway", "monitoring", "stackrox", "billing", "model-registry"]
    apps = {"ai-inference": ["triton-server", "vllm-router", "llm-gateway"], "training-jobs": ["pytorch-operator", "ray-head", "ray-worker"],
            "jupyter-hub": ["hub", "proxy", "user-scheduler"], "api-gateway": ["kong", "auth-svc", "rate-limiter"],
            "monitoring": ["prometheus", "grafana", "node-exporter", "dcgm-exporter"], "stackrox": ["sensor", "collector", "admission-control"],
            "billing": ["invoice-api", "usage-collector"], "model-registry": ["mlflow", "minio"]}
    images, deployments, pods, nodes, namespaces = {}, [], [], [], []

    def make_image(name):
        if name in images:
            return images[name]
        comps = []
        for pkg, ver in R.sample(COMMON_PKGS, R.randint(5, 10)):
            comps.append({"name": pkg, "version": ver, "source": "OS", "location": "", "vulns": rand_vulns(R.choice([0, 0, 1, 2, 4]))})
        for cve, pkg, ver, fix, cvss, s, summ, src in FAMOUS:
            if R.random() < 0.18:
                loc = "/app/lib/log4j-core-2.14.1.jar" if src == "JAVA" else "/usr/bin/app" if src == "GO" else ""
                comps.append({"name": pkg, "version": ver, "source": src, "location": loc,
                              "vulns": [vuln(cve, SEV[s], cvss, summ, fix)]})
        reg, remote_tag = name.split("/", 1)
        remote, tag = remote_tag.rsplit(":", 1)
        img = {"id": sha(name), "name": {"registry": reg, "remote": remote, "tag": tag, "fullName": name},
               "names": [{"registry": reg, "remote": remote, "tag": tag, "fullName": name}],
               "metadata": {"v1": {"created": "2026-0%d-1%dT08:00:00Z" % (R.randint(1, 9), R.randint(0, 9))}},
               "scan": {"scanTime": "2026-10-07T01:%02d:00Z" % R.randint(0, 59), "operatingSystem": R.choice(["rhel:9", "ubuntu:22.04", "alpine:3.18", "debian:12"]),
                        "components": comps}, "notes": []}
        images[name] = img
        return img

    for c in clusters:
        node_names = [f"{c['name']}-{'gpu' if i < 4 else 'cpu'}-{i:02d}" for i in range(6)]
        for i, nn in enumerate(node_names):
            comps = [{"name": "kernel", "version": "5.14.0-427.el9", "vulns": rand_vulns(R.randint(0, 3))},
                     {"name": "runc", "version": "1.1.12", "vulns": rand_vulns(R.randint(0, 1))},
                     {"name": "nvidia-container-toolkit", "version": "1.16.1",
                      "vulnerabilities": [{"cveBaseInfo": {"cve": "CVE-2024-0132", "summary": "NVIDIA Container Toolkit TOCTOU container escape.",
                                                           "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-0132", "publishedOn": "2024-09-26T00:00:00Z"},
                                          "cvss": 9.0, "severity": SEV[0], "fixedBy": "1.16.2"}] if i < 4 else []}]
            if R.random() < 0.4:
                comps.append({"name": "openssh", "version": "9.6p1", "vulns": [vuln(*[FAMOUS[3][0], SEV[1], 8.1, FAMOUS[3][6], "9.8p1"])]})
            nodes.append({"id": f"node-{nn}", "name": nn, "clusterId": c["id"], "clusterName": c["name"],
                          "osImage": "Red Hat Enterprise Linux CoreOS 417.94", "kernelVersion": "5.14.0-427.el9.x86_64",
                          "containerRuntimeVersion": "cri-o://1.30.4", "kubeletVersion": "v1.30.6",
                          "internalIpAddresses": [f"10.129.{10 if c['id']=='c-sg-prod' else 20}.{i+11}"], "externalIpAddresses": [],
                          "labels": {"node-role.kubernetes.io/worker": "", "nvidia.com/gpu.present": str(i < 4).lower()},
                          "joinedAt": "2026-03-01T00:00:00Z", "scan": {"scanTime": "2026-10-07T00:00:00Z", "components": comps}})
        for ns in ns_names:
            nsid = f"ns-{c['id']}-{ns}"
            namespaces.append({"metadata": {"id": nsid, "name": ns, "clusterId": c["id"], "clusterName": c["name"],
                                            "labels": {"kubernetes.io/metadata.name": ns}, "creationTime": "2026-01-15T00:00:00Z"},
                               "numDeployments": len(apps[ns]), "numNetworkPolicies": R.randint(0, 4)})
            for app in apps[ns]:
                img = make_image(f"registry.bitdeer.local/{ns}/{app}:{R.choice(['1.4.2', '2.0.1', 'v3.1', 'latest'])}")
                did = f"dep-{c['id']}-{ns}-{app}"
                exp = R.choice(["UNSET", "UNSET", "INTERNAL", "NODE", "EXTERNAL", "ROUTE"])
                deployments.append({
                    "id": did, "name": app, "type": "DaemonSet" if app in ("node-exporter", "dcgm-exporter", "collector") else "Deployment",
                    "namespace": ns, "namespaceId": nsid, "clusterId": c["id"], "clusterName": c["name"],
                    "labels": {"app": app}, "serviceAccount": app, "riskScore": round(R.uniform(1, 12), 2),
                    "created": "2026-05-01T00:00:00Z", "hostNetwork": app in ("node-exporter", "collector"),
                    "containers": [{"name": app, "image": {"id": img["id"], "name": img["name"]},
                                    "securityContext": {"privileged": app in ("collector", "dcgm-exporter")}}],
                    "ports": [{"containerPort": 8080, "protocol": "TCP", "exposure": exp}] if exp != "UNSET" else []})
                for k in range(R.randint(1, 3)):
                    pods.append({"id": f"pod-{did}-{k}", "name": f"{app}-{k}", "deploymentId": did, "namespace": ns, "clusterId": c["id"],
                                 "liveInstances": [{"instanceId": {"id": f"cid{k}", "node": R.choice(node_names)},
                                                    "containerName": app, "imageDigest": img["id"]}]})
    # an image that is scanned but not deployed
    make_image("registry.bitdeer.local/legacy/old-api:0.9")
    return clusters, namespaces, deployments, list(images.values()), nodes, pods


def create_app():
    clusters, namespaces, deployments, images, nodes, pods = build()
    app = Flask(__name__)

    @app.before_request
    def auth():
        if not request.headers.get("Authorization", "").startswith("Bearer "):
            return jsonify({"error": "unauthenticated"}), 401

    def stream(key, items):
        return Response(("".join(json.dumps({"result": {key: i}}) + "\n" for i in items)), mimetype="application/json")

    app.add_url_rule("/v1/clusters", "c", lambda: jsonify({"clusters": clusters}))
    app.add_url_rule("/v1/namespaces", "ns", lambda: jsonify({"namespaces": namespaces}))
    app.add_url_rule("/v1/export/deployments", "d", lambda: stream("deployment", deployments))
    app.add_url_rule("/v1/export/images", "i", lambda: stream("image", images))
    app.add_url_rule("/v1/export/nodes", "n", lambda: stream("node", nodes))
    app.add_url_rule("/v1/export/pods", "p", lambda: stream("pod", pods))

    # --- SBOM (RHACS 4.7+ Scanner V4): POST /api/v1/images/sbom {"imageName": ...} -> SPDX 2.3
    LIC = {"openssl": "Apache-2.0", "glibc": "LGPL-2.1-or-later", "zlib": "Zlib", "curl": "curl", "bash": "GPL-3.0-or-later",
           "libxml2": "MIT", "python3": "Python-2.0", "ncurses": "MIT", "sqlite": "blessing", "nghttp2": "MIT",
           "expat": "MIT", "krb5-libs": "MIT", "systemd-libs": "LGPL-2.1-or-later", "xz": "0BSD AND GPL-2.0-or-later",
           "log4j-core": "Apache-2.0", "golang.org/x/net": "BSD-3-Clause", "openssh": "BSD-2-Clause"}
    by_name = {i["name"]["fullName"]: i for i in images}

    @app.post("/api/v1/images/sbom")
    def sbom():
        img = by_name.get((request.get_json(silent=True) or {}).get("imageName"))
        if not img:
            return jsonify({"error": "image not found"}), 404
        osn = img["scan"]["operatingSystem"].split(":")[0]
        typ = {"rhel": ("rpm", "redhat"), "ubuntu": ("deb", "ubuntu"), "debian": ("deb", "debian"), "alpine": ("apk", "alpine")}[osn]
        pk = [{"SPDXID": "SPDXRef-img", "name": img["name"]["remote"], "versionInfo": img["name"]["tag"],
               "primaryPackagePurpose": "CONTAINER", "downloadLocation": "NOASSERTION"}]
        comps = img["scan"]["components"] + [{"name": "ca-certificates", "version": "2024.2.69", "source": "OS"},
                                             {"name": "tzdata", "version": "2024a", "source": "OS"}]
        for k, c in enumerate(comps):
            src = c.get("source", "OS")
            purl = (f"pkg:maven/org.apache.logging.log4j/{c['name']}@{c['version']}" if src == "JAVA" else
                    f"pkg:golang/{c['name']}@{c['version']}" if src == "GO" else
                    f"pkg:{typ[0]}/{typ[1]}/{c['name']}@{c['version']}")
            pk.append({"SPDXID": f"SPDXRef-Package-{k}", "name": c["name"], "versionInfo": c["version"],
                       "supplier": "Organization: Red Hat" if typ[1] == "redhat" and src == "OS" else "NOASSERTION",
                       "licenseConcluded": "NOASSERTION", "licenseDeclared": LIC.get(c["name"], "NOASSERTION"),
                       "downloadLocation": "NOASSERTION", "primaryPackagePurpose": "LIBRARY",
                       "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}]})
        return jsonify({"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
                        "name": img["name"]["fullName"], "creationInfo": {"created": "2026-10-07T09:00:00Z",
                                                                            "creators": ["Tool: Red Hat Advanced Cluster Security - 4.8.2"]},
                        "packages": pk})
    return app


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8443)
    create_app().run(port=ap.parse_args().port)

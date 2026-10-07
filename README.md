# RHACS Asset Inventory & CVE Impact Explorer

Two pieces:

1. **`collector/rhacs_collector.py`** — pulls every asset from RHACS Central (clusters, namespaces, nodes, deployments, pods, images, components, CVEs) and writes one normalized, ID-linked JSON file (+ optional flat CSV for SIEM ingestion).
2. **`webapp/app.py`** — Flask web UI that reads that file, links everything together, and answers *"this CVE / package just dropped — what is affected, where, and how exposed?"*

```
Cluster ─┬─ Node ── OS packages ── CVEs
         └─ Namespace ── Deployment ─┬─ Pods ── Node
                                     └─ Container ── Image ── Packages ── CVEs
```

## Quick start

```bash
pip install -r requirements.txt

# 1. Create an API token in RHACS: Platform Configuration → Integrations → API Token
#    Role "Analyst" (read-only) is sufficient.
export ROX_CENTRAL_ADDRESS=central.example.internal:443
export ROX_API_TOKEN='eyJ...'

# 2. Collect (add --sbom to pull official SPDX SBOMs - RHACS 4.7+ with Scanner V4)
python collector/rhacs_collector.py --out data/assets.json --csv data/cve_impact.csv --sbom \
       --ca-cert /path/to/central-ca.pem        # or --insecure in a lab

# 3. Serve the UI
python webapp/app.py --data data/assets.json    # http://127.0.0.1:8088
```

To expose to the SOC team, put it behind your reverse proxy / SSO, or at minimum:
`APP_USER=soc APP_PASSWORD='…' python webapp/app.py --host 0.0.0.0`

### Keep it fresh
The webapp auto-reloads whenever the JSON file changes (the collector writes atomically). Schedule the collector, e.g. cron every 2 h:
```cron
0 */2 * * *  cd /opt/rhacs-asset-inventory && ROX_API_TOKEN=$(cat /etc/rhacs/token) python3 collector/rhacs_collector.py --central central.example.internal:443 --ca-cert /etc/rhacs/ca.pem --out data/assets.json --csv data/cve_impact.csv >> /var/log/rhacs-collector.log 2>&1
```

## Try it without RHACS
```bash
python tools/mock_central.py --port 8443 &
ROX_API_TOKEN=dummy python collector/rhacs_collector.py --central http://127.0.0.1:8443 --out data/assets.json
python webapp/app.py
```
The mock includes real-world CVEs to demo with: `CVE-2024-3094` (xz), `CVE-2021-44228` (Log4Shell), `CVE-2024-0132` (NVIDIA Container Toolkit, on GPU nodes), `CVE-2024-6387` (regreSSHion).

## What the UI does

| Page | Use it for |
|---|---|
| **Overview** | Asset counts, severity mix, *internet-exposed workloads with Critical CVEs*, top CVEs by blast radius |
| **CVE Impact** | Paste 1–100 CVE/advisory IDs → per-CVE blast radius (clusters, namespaces, deployments, images, nodes, exposed, privileged) and the full chain cluster → namespace → deployment → node → image → package → fixed version. Export CSV for tickets. |
| **SBOM Map** | Search one package → interactive map: package versions → images / hosts → deployments → namespaces → clusters. Hover traces the path; click any box for its details (purl, license, supplier, file locations, CVEs + fixed versions; or image digest / SBOM download; or exposure / risk). |
| **Package Hunt** | Zero-days before scanners catch up: find every image/node with e.g. `xz` `5.6`, `log4j-core` `2.14` |
| **CVEs** | Catalog filtered by severity / fixability, ranked by impact |
| **Clusters / Images / Nodes** | Drill-down; every asset links to its related assets |

Workload rows are pre-sorted by exposure (EXTERNAL/ROUTE first) then RHACS risk score, so the first rows are what to patch first.

## SBOM
- `--sbom` calls `POST /api/v1/images/sbom` (`{"imageName": "...", "force": false}`) for every **deployed** image (`--sbom-all` adds undeployed ones). This is the same endpoint `roxctl image sbom` uses; it needs RHACS 4.7+ with Scanner V4. If your version exposes it at a different path, set `--sbom-endpoint`.
- Raw SPDX 2.3 documents are kept in `data/sbom/<digest>.spdx.json`; purl, license, supplier and CPE are merged into each image's package list, and SBOM-only packages (no CVEs) are added.
- If Central has no SBOM endpoint, the collector logs a warning and continues: every package still gets a **derived purl** (`pkg:rpm/redhat/…`, `pkg:maven/…`, `pkg:golang/…`) from the scan data, marked `purlSource: "derived"`.
- Each image page offers **SPDX 2.3** (official file when collected, otherwise generated) and **CycloneDX 1.5** (generated, includes vulnerabilities) downloads: `GET /api/sbom/<digest>?format=spdx|cyclonedx`.

## RHACS APIs used
| Data | Endpoint | Fallback (older Central) |
|---|---|---|
| Clusters | `GET /v1/clusters` | – |
| Namespaces | `GET /v1/namespaces` | – |
| Deployments | `GET /v1/export/deployments` (stream) | `/v1/deployments` + `/v1/deployments/{id}` |
| Pods (→ node placement) | `GET /v1/export/pods` (stream) | `/v1/pods` |
| Images + CVEs | `GET /v1/export/images` (stream) | `/v1/images` + `/v1/images/{id}` |
| Nodes + CVEs | `GET /v1/export/nodes` (stream) | `/v1/nodes/{clusterId}` |
| SBOM (optional) | `POST /api/v1/images/sbom` | derived purls from scan data |

Scope a run with `--query "Cluster:sg-gpu-prod"` (standard RHACS search syntax). Large environments: raise `--timeout`.

## Output files
- `assets.json` — schema documented at the top of `rhacs_collector.py`. Relationships are by ID (`deployment.containers[].imageId → images[].id`, `component.vulns[].cve → cves{}`), so it can also be loaded into a graph DB or CMDB.
- `cve_impact.csv` — one row per CVE × package × asset (image/deployment/node). Ready for OpenSearch ingestion (`collected_at` as the timestamp field) to correlate with runtime detections.

## Known limits
- Cluster-level CVEs (Kubernetes/OpenShift platform CVEs) are not collected yet — add `/v1/clustercves` or the GraphQL endpoint if needed.
- Deployments whose image was referenced by tag and never scanned show as "not scanned".
- Data is a snapshot as of the last collector run (shown top-right in the UI).

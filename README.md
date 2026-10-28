# CyberSoul AlertEye — Working MVP

A local-first security operations prototype for triaging events from existing CCTV/VMS/NVR workflows. Includes a responsive incident dashboard, rule-based threat prioritization, persistent SQLite storage, video evidence upload, human review, audit trail, JSON APIs, deduplication, and CSV export.

> **Honest capability boundary:** This version does not run a computer-vision model on video, connect to RTSP/IP cameras, or automatically verify an incident. Demo scenarios are synthetic; uploaded videos are stored for manual review. Confidence values may be supplied by an upstream alert source. Threat scores are transparent rule-based triage scores, not calibrated probabilities or validated AI predictions.

## Run on Windows

1. Install Python 3.11+ from https://www.python.org/downloads/ and enable **Add Python to PATH** during installation.
2. Extract this folder somewhere writable, e.g. `C:\CyberSoul_AlertEye_MVP`.
3. Open Command Prompt in that folder and run:

```bat
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```

4. Open http://127.0.0.1:8000
5. Click **Run demo scenarios**, open an incident, test status/review updates, upload a clip, and export CSV.

If `py` is not recognized, install Python from the official site and reopen Command Prompt. If you already have a working Python virtual environment, activate it and install `requirements.txt` there.

## Run on macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

## Main capabilities

- SQLite-backed incidents and audit events persist across restarts.
- Dashboard filters by text, severity, and status.
- Demo event generator creates six synthetic scenarios.
- Operator workflow: New → Assigned → Acknowledged → Investigating → Escalated / Resolved → Closed (statuses can be changed as needed).
- Human review labels: Genuine, False positive, Duplicate, Uncertain.
- Local upload of MP4/MOV/AVI/MKV/WEBM files (250 MB maximum); clips are not automatically analyzed.
- CSV export of incidents.
- API for importing normalized events and updating operator review.
- Event-key deduplication and a basic audit trail.

## API

Health check:
```bash
curl http://127.0.0.1:8000/api/health
```

List incidents:
```bash
curl http://127.0.0.1:8000/api/incidents
```

Create an incident:
```bash
curl -X POST http://127.0.0.1:8000/api/incidents -H "Content-Type: application/json" -d "{\"event_key\":\"vms-123\",\"camera\":\"CAM-01\",\"location\":\"North Gate\",\"event_type\":\"Intrusion\",\"confidence\":0.88,\"summary\":\"Restricted zone event from VMS\"}"
```

Import a JSON array (up to 1,000 records per request):
```bash
curl -X POST http://127.0.0.1:8000/api/import -H "Content-Type: application/json" --data-binary @sample_events.json
```

Update status/review:
```bash
curl -X PATCH http://127.0.0.1:8000/api/incidents/1 -H "Content-Type: application/json" -d "{\"status\":\"Investigating\",\"review_label\":\"Genuine\",\"reviewer_note\":\"Verified by operator\"}"
```

## Security / deployment notes

This is a development prototype, not production-ready for deployment on the public internet. It has no user authentication, role-based access control, TLS configuration, retention policy, or hardened multi-tenant isolation. Keep it on localhost or a trusted isolated network; use only footage you are authorized to process. Before any real deployment, add authentication, CSRF protection, access controls, encrypted transport/storage, secrets management, audit-log integrity, configurable retention/deletion, monitoring, and a reviewed threat model.

## Next engineering milestone for real video intelligence

Add a separate detector worker that samples frames from an authorized uploaded clip, runs a validated person/object detector, tracks objects across frames, evaluates explicitly configured restricted zones, saves timestamped evidence frames, and emits normalized events through `/api/incidents`. Evaluate against a labeled test set and report precision/recall and false alerts per camera before presenting it as operational AI.

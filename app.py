from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, send_from_directory, Response
from werkzeug.utils import secure_filename
from pathlib import Path
from datetime import datetime, timezone
import sqlite3, json, csv, io, os, hashlib

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / 'alerteye.db'
UPLOAD_DIR = BASE / 'uploads'
UPLOAD_DIR.mkdir(exist_ok=True)
ALLOWED_VIDEO = {'.mp4', '.mov', '.avi', '.mkv', '.webm'}
STATUSES = ['New', 'Assigned', 'Acknowledged', 'Investigating', 'Escalated', 'Resolved', 'Closed']
LABELS = ['Genuine', 'False positive', 'Duplicate', 'Uncertain']
app = Flask(__name__)
app.secret_key = os.environ.get('ALERTEYE_SECRET_KEY', 'local-demo-change-this-secret')
app.config['MAX_CONTENT_LENGTH'] = 250 * 1024 * 1024


def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def connect():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with connect() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT, event_key TEXT UNIQUE, created_at TEXT NOT NULL,
            camera TEXT NOT NULL, location TEXT NOT NULL, event_type TEXT NOT NULL,
            confidence REAL NOT NULL, threat_score INTEGER NOT NULL, severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'New', summary TEXT NOT NULL, evidence_file TEXT,
            review_label TEXT, reviewer_note TEXT, updated_at TEXT NOT NULL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL,
            at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, details TEXT,
            FOREIGN KEY(incident_id) REFERENCES incidents(id))''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at DESC)')

def threat_score(event_type, confidence):
    base = {'Fight / violence': 75, 'Intrusion': 70, 'Fall / accident': 68,
            'Restricted-zone entry': 65, 'Crowd density': 52, 'Suspicious activity': 45,
            'Unknown event': 30}.get(event_type, 30)
    return max(0, min(100, round(base * 0.65 + float(confidence) * 35)))

def severity_for(score): return 'Critical' if score >= 80 else 'High' if score >= 65 else 'Medium' if score >= 40 else 'Low'

def log(db, incident_id, action, details='System event'):
    db.execute('INSERT INTO audit_log(incident_id,at,actor,action,details) VALUES(?,?,?,?,?)',
               (incident_id, now(), request.headers.get('X-Actor', 'Operator'), action, details))

def create_incident(data, db=None):
    own = db is None
    db = db or connect()
    event_type = str(data.get('event_type') or data.get('type') or 'Unknown event')[:100]
    confidence = max(0.0, min(1.0, float(data.get('confidence', 0.7))))
    score = int(data.get('threat_score') or threat_score(event_type, confidence))
    score = max(0, min(100, score))
    timestamp = str(data.get('created_at') or data.get('timestamp') or now())[:80]
    camera = str(data.get('camera') or data.get('source') or 'CAM-01')[:100]
    location = str(data.get('location') or camera)[:160]
    summary = str(data.get('summary') or data.get('description') or f'{event_type} detected on {camera}')[:500]
    key = str(data.get('event_key') or hashlib.sha256(f'{timestamp}|{camera}|{event_type}|{summary}'.encode()).hexdigest())[:128]
    severity = severity_for(score)
    try:
        cur = db.execute('''INSERT INTO incidents(event_key,created_at,camera,location,event_type,confidence,threat_score,severity,status,summary,evidence_file,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''', (key,timestamp,camera,location,event_type,confidence,score,severity,'New',summary,data.get('evidence_file'),now()))
        iid = cur.lastrowid
        log(db, iid, 'Created', f'Incident created from {data.get("source_kind", "manual/demo/import")}')
        if own: db.commit()
        return iid, False
    except sqlite3.IntegrityError:
        row = db.execute('SELECT id FROM incidents WHERE event_key=?', (key,)).fetchone()
        if own: db.commit()
        return row['id'], True
    finally:
        if own: db.close()

@app.route('/')
def dashboard():
    with connect() as db:
        incidents = db.execute('SELECT * FROM incidents ORDER BY created_at DESC, id DESC LIMIT 100').fetchall()
        counts = {r['severity']: r['n'] for r in db.execute('SELECT severity,COUNT(*) n FROM incidents GROUP BY severity')}
        status_counts = {r['status']:r['n'] for r in db.execute('SELECT status,COUNT(*) n FROM incidents GROUP BY status')}
        total = db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0]
        open_count = db.execute("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('Resolved','Closed')").fetchone()[0]
        avg = db.execute('SELECT AVG(threat_score) FROM incidents').fetchone()[0]
    return render_template('dashboard.html', incidents=incidents, counts=counts, status_counts=status_counts,
                           total=total, open_count=open_count, avg=round(avg or 0), statuses=STATUSES, labels=LABELS)

@app.route('/incidents/<int:iid>')
def incident_detail(iid):
    with connect() as db:
        incident = db.execute('SELECT * FROM incidents WHERE id=?',(iid,)).fetchone()
        if not incident: return 'Incident not found', 404
        logs = db.execute('SELECT * FROM audit_log WHERE incident_id=? ORDER BY id DESC',(iid,)).fetchall()
    return render_template('incident.html', incident=incident, logs=logs, statuses=STATUSES, labels=LABELS)

@app.post('/incidents/<int:iid>/update')
def update_incident(iid):
    status = request.form.get('status','')
    label = request.form.get('review_label') or None
    note = request.form.get('reviewer_note','').strip()[:1000]
    if status not in STATUSES or (label and label not in LABELS):
        flash('Invalid status or review label.', 'error'); return redirect(url_for('incident_detail', iid=iid))
    with connect() as db:
        row = db.execute('SELECT * FROM incidents WHERE id=?',(iid,)).fetchone()
        if not row: return 'Incident not found', 404
        db.execute('UPDATE incidents SET status=?,review_label=?,reviewer_note=?,updated_at=? WHERE id=?',
                   (status,label,note,now(),iid))
        if row['status'] != status: log(db,iid,'Status changed',f'{row["status"]} → {status}')
        if label or note: log(db,iid,'Human review',f'Label: {label or "not set"}; Note: {note or "none"}')
    flash('Incident updated.', 'success'); return redirect(url_for('incident_detail', iid=iid))

@app.post('/demo/generate')
def demo_generate():
    scenarios = [
      ('Intrusion',.91,'CAM-01','North entrance','Person entered a configured restricted zone.'),
      ('Crowd density',.83,'CAM-02','Main lobby','Crowd density crossed the demo threshold.'),
      ('Fight / violence',.78,'CAM-03','Parking level B1','Possible physical altercation flagged for operator review.'),
      ('Fall / accident',.86,'CAM-04','East corridor','Possible fall or sudden downward movement.'),
      ('Suspicious activity',.63,'CAM-05','Loading bay','Unusual dwell time near a sensitive access point.'),
      ('Restricted-zone entry',.95,'CAM-06','Server-room corridor','Movement detected inside a restricted zone.')]
    created=0; duplicates=0
    for idx,(typ,conf,cam,loc,summary) in enumerate(scenarios):
        iid, dup = create_incident({'event_key':f'demo-{datetime.now().strftime("%Y%m%d%H%M")}-{idx}', 'event_type':typ,'confidence':conf,'camera':cam,'location':loc,'summary':summary,'source_kind':'demo scenario'})
        duplicates += int(dup); created += int(not dup)
    flash(f'Demo run complete: {created} incidents created.', 'success')
    return redirect(url_for('dashboard'))

@app.post('/upload/video')
def upload_video():
    f = request.files.get('video')
    if not f or not f.filename:
        flash('Choose a video file first.', 'error'); return redirect(url_for('dashboard'))
    ext = Path(secure_filename(f.filename)).suffix.lower()
    if ext not in ALLOWED_VIDEO:
        flash('Unsupported video type. Use MP4, MOV, AVI, MKV or WEBM.', 'error'); return redirect(url_for('dashboard'))
    safe_name = f'{datetime.now().strftime("%Y%m%d%H%M%S")}_{secure_filename(f.filename)}'
    target = UPLOAD_DIR / safe_name
    f.save(target)
    create_incident({'event_key':f'upload-{safe_name}','event_type':'Video uploaded for review','confidence':0.0,'threat_score':10,'camera':'Uploaded clip','location':'Local upload','summary':f'Uploaded file {safe_name}. This MVP stores the clip but does not automatically analyze it.','evidence_file':safe_name,'source_kind':'video upload'})
    flash('Video stored locally and added to the review queue. Automated video analysis is not enabled in this build.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=False)

@app.get('/export.csv')
def export_csv():
    with connect() as db: rows = db.execute('SELECT * FROM incidents ORDER BY created_at DESC').fetchall()
    out=io.StringIO(); writer=csv.writer(out)
    if rows:
        writer.writerow(rows[0].keys())
        for r in rows: writer.writerow([r[k] for k in r.keys()])
    return Response(out.getvalue(), mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=alerteye_incidents.csv'})

@app.get('/api/health')
def health(): return jsonify({'ok':True,'service':'CyberSoul AlertEye MVP','time':now()})
@app.get('/api/incidents')
def api_incidents():
    with connect() as db: rows=db.execute('SELECT * FROM incidents ORDER BY created_at DESC LIMIT 500').fetchall()
    return jsonify([dict(r) for r in rows])
@app.post('/api/incidents')
def api_create():
    data=request.get_json(silent=True)
    if not isinstance(data,dict): return jsonify({'error':'Send a JSON object.'}),400
    try: iid, duplicate=create_incident(data)
    except (ValueError,TypeError): return jsonify({'error':'confidence and threat_score must be numeric when provided.'}),400
    with connect() as db: row=db.execute('SELECT * FROM incidents WHERE id=?',(iid,)).fetchone()
    return jsonify({'incident':dict(row),'duplicate':duplicate}), (200 if duplicate else 201)
@app.patch('/api/incidents/<int:iid>')
def api_update(iid):
    data=request.get_json(silent=True) or {}
    status=data.get('status'); label=data.get('review_label'); note=str(data.get('reviewer_note',''))[:1000]
    if status is not None and status not in STATUSES: return jsonify({'error':'Invalid status','allowed':STATUSES}),400
    if label is not None and label not in LABELS: return jsonify({'error':'Invalid review_label','allowed':LABELS}),400
    with connect() as db:
        row=db.execute('SELECT * FROM incidents WHERE id=?',(iid,)).fetchone()
        if not row: return jsonify({'error':'Not found'}),404
        new_status=status or row['status']; new_label=label if label is not None else row['review_label']; new_note=note if 'reviewer_note' in data else row['reviewer_note']
        db.execute('UPDATE incidents SET status=?,review_label=?,reviewer_note=?,updated_at=? WHERE id=?',(new_status,new_label,new_note,now(),iid))
        if new_status != row['status']: log(db,iid,'Status changed',f'{row["status"]} → {new_status}')
        if label is not None or 'reviewer_note' in data: log(db,iid,'Human review',f'Label: {new_label or "not set"}; Note: {new_note or "none"}')
        updated=db.execute('SELECT * FROM incidents WHERE id=?',(iid,)).fetchone()
    return jsonify(dict(updated))
@app.post('/api/import')
def api_import():
    data=request.get_json(silent=True)
    if not isinstance(data,list): return jsonify({'error':'Send a JSON array of event objects.'}),400
    created=duplicates=0; errors=[]
    for i,item in enumerate(data[:1000]):
        if not isinstance(item,dict): errors.append({'row':i,'error':'Expected object'}); continue
        try:
            _,dup=create_incident(item); duplicates+=int(dup); created+=int(not dup)
        except (ValueError,TypeError) as e: errors.append({'row':i,'error':str(e)})
    return jsonify({'received':min(len(data),1000),'created':created,'duplicates':duplicates,'errors':errors,'truncated':len(data)>1000}),201

@app.errorhandler(413)
def too_large(_): return 'File exceeds the 250 MB upload limit.',413

init_db()
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=int(os.environ.get('PORT','8000')), debug=False)

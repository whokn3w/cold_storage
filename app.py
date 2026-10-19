import os, re, json, sqlite3, pathlib, datetime, threading, html, urllib.parse, shutil
from zoneinfo import ZoneInfo
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from contextlib import closing

DB = os.getenv('DB_PATH', '/config/cold_storage.db')
DEVICES = pathlib.Path(os.getenv('DEVICES_PATH', '/records/devices'))
BACKUPS = pathlib.Path(os.getenv('BACKUPS_PATH', '/backups'))
PORT = int(os.getenv('PORT', '8080'))
APP_VERSION = '0.5.0-dev'
LOCK = threading.Lock()
UTC = datetime.timezone.utc
LOCAL_TZ = ZoneInfo(os.environ.get("TZ", "America/Detroit"))

def connect():
    db=sqlite3.connect(DB, timeout=30)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA busy_timeout=30000')
    return db

def init():
    pathlib.Path(DB).parent.mkdir(parents=True, exist_ok=True)
    with closing(connect()) as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS drives (id TEXT PRIMARY KEY, model TEXT, serial TEXT, capacity INTEGER, registered TEXT, interval_days INTEGER, file_count INTEGER, last_pass TEXT, last_verify TEXT, last_result TEXT, pending INTEGER, latest_registration TEXT);
        CREATE TABLE IF NOT EXISTS files (drive_id TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(drive_id,path));
        CREATE INDEX IF NOT EXISTS files_path ON files(path COLLATE NOCASE);
        CREATE TABLE IF NOT EXISTS runs (drive_id TEXT, seq INTEGER, stamp TEXT, action TEXT, result TEXT, tracked INTEGER, delta INTEGER, issues INTEGER, PRIMARY KEY(drive_id,seq));
        CREATE TABLE IF NOT EXISTS issues (drive_id TEXT, seq INTEGER, raw TEXT, PRIMARY KEY(drive_id,seq));
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY,value TEXT);
        CREATE TABLE IF NOT EXISTS storage_snapshots (drive_id TEXT PRIMARY KEY, used_bytes INTEGER NOT NULL, available_bytes INTEGER NOT NULL, captured_at TEXT NOT NULL, FOREIGN KEY(drive_id) REFERENCES drives(id));
        ''')
        db.commit()

def parse_manifest(path):
    result=[]
    with path.open('r', encoding='utf-8', errors='strict', newline='') as fh:
        for line_no, line in enumerate(fh,1):
            line=line.rstrip('\n')
            if not line: continue
            # GNU sha256sum escapes newline/backslash and prefixes the hash with a backslash.
            escaped=line.startswith('\\')
            if escaped: line=line[1:]
            match=re.fullmatch(r'([0-9a-fA-F]{64}) ([ *])(.*)', line)
            if not match: raise ValueError(f'Invalid SHA-256 manifest line {line_no}')
            name=match.group(3)
            if escaped:
                # GNU coreutils uses \\ and \n escapes in filenames.
                chars=[]; i=0
                while i<len(name):
                    if name[i]=='\\':
                        i+=1
                        if i>=len(name) or name[i] not in ('\\','n'):
                            raise ValueError(f'Invalid filename escape on line {line_no}')
                        chars.append('\n' if name[i]=='n' else '\\')
                    else: chars.append(name[i])
                    i+=1
                name=''.join(chars)
            if not name.startswith('./') or '\x00' in name or '\r' in name:
                raise ValueError(f'Unsafe path on manifest line {line_no}')
            relative=name[2:]
            if not relative or any(x in ('.','..') for x in relative.split('/')) or relative.startswith('/'):
                raise ValueError(f'Unsafe path on manifest line {line_no}')
            result.append((relative,match.group(1).lower()))
    if len(result)!=len(set(p for p,h in result)):
        raise ValueError('Duplicate file paths in manifest')
    return result

def read_runs(path):
    out=[]
    if not path.is_file(): return out
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip():continue
        parts=line.split('\t')
        if len(parts)<6: parts=line.split()
        if len(parts)<6: continue
        try: out.append((parts[0],parts[1],parts[2],int(parts[3]),int(parts[4]),int(parts[5])))
        except ValueError: continue
    return out

def read_issues(path):
    if not path.is_file(): return []
    return path.read_text(encoding='utf-8',errors='replace').splitlines()

def refresh():
    # Parse and validate ALL sources before changing the DB.
    parsed=[]; errors=[]
    if not DEVICES.is_dir(): return 0,[f'Device directory unavailable: {DEVICES}']
    for folder in sorted(DEVICES.iterdir()):
        if not folder.is_dir(): continue
        meta=folder/'device.json'
        if not meta.is_file(): continue
        try:
            data=json.loads(meta.read_text(encoding='utf-8'))
            ident=data['device_id']
            if ident!=folder.name: raise ValueError('Device ID does not match directory')
            manifest=folder/'manifests'/'baseline.sha256'
            files=parse_manifest(manifest) if manifest.is_file() else []
            runs=read_runs(folder/'verification_logs'/'runs.tsv')
            issues=read_issues(folder/'verification_logs'/'issues.tsv')
            parsed.append((data,files,runs,issues))
        except Exception as e: errors.append(f'{folder.name}: {e}')
    if errors: return 0,errors
    snapshots,storage_messages=collect_storage_snapshots(parsed)
    with LOCK:
        with closing(connect()) as db:
            try:
                db.execute('BEGIN IMMEDIATE')
                for data,files,runs,issues in parsed:
                    ident=data['device_id']
                    ver=[r for r in runs if r[1]=='verify']
                    last_ver=ver[-1] if ver else None
                    passed=[r for r in ver if r[2]=='PASS']
                    last_pass=passed[-1][0] if passed else None
                    regs=[r for r in runs if r[1]=='register' and r[2]=='PASS']
                    last_reg=regs[-1][0] if regs else None
                    pending=int(bool(last_reg and (not last_pass or last_reg>last_pass)))
                    db.execute('''INSERT INTO drives VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET model=excluded.model,serial=excluded.serial,capacity=excluded.capacity,registered=excluded.registered,interval_days=excluded.interval_days,file_count=excluded.file_count,last_pass=excluded.last_pass,last_verify=excluded.last_verify,last_result=excluded.last_result,pending=excluded.pending,latest_registration=excluded.latest_registration''',
                        (ident,data.get('model'),data.get('serial'),data.get('capacity_bytes'),data.get('registered_at'),data.get('verification_interval_days',180),len(files),last_pass,last_ver[0] if last_ver else None,last_ver[2] if last_ver else None,pending,last_reg))
                    db.execute('DELETE FROM files WHERE drive_id=?',(ident,))
                    db.executemany('INSERT INTO files VALUES (?,?,?)',((ident,p,h) for p,h in files))
                    db.execute('DELETE FROM runs WHERE drive_id=?',(ident,))
                    db.executemany('INSERT INTO runs VALUES (?,?,?,?,?,?,?,?)',((ident,i,*r) for i,r in enumerate(runs)))
                    db.execute('DELETE FROM issues WHERE drive_id=?',(ident,))
                    db.executemany('INSERT INTO issues VALUES (?,?,?)',((ident,i,line) for i,line in enumerate(issues)))
                db.execute('INSERT INTO meta VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',('storage_refresh_report',json.dumps(storage_messages)))
                db.executemany('''INSERT INTO storage_snapshots(drive_id,used_bytes,available_bytes,captured_at) VALUES (?,?,?,?) ON CONFLICT(drive_id) DO UPDATE SET used_bytes=excluded.used_bytes,available_bytes=excluded.available_bytes,captured_at=excluded.captured_at''', snapshots)
                db.execute('INSERT INTO meta VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',('last_refresh',datetime.datetime.now(UTC).isoformat(timespec='seconds')))
                db.commit()
            except:
                db.rollback();raise
    return len(parsed),[]

# Only mounted Unassigned Devices filesystems with an exact matching udev ATA
# hardware identity are eligible. Never open raw block devices or scan files.
ARCHIVE_MOUNTS = pathlib.Path(os.getenv('ARCHIVE_MOUNTS', '/archive-mounts'))
DISK_BY_ID = pathlib.Path(os.getenv('DISK_BY_ID', '/host-disk-by-id'))

def mounted_sources():
    """Return exact mount entries, including the kernel major:minor identity."""
    result = {}
    for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines():
        left, sep, right = line.partition(' - ')
        if not sep:
            continue
        fields, after = left.split(), right.split()
        if len(fields) < 5 or len(after) < 2:
            continue
        mount = fields[4].replace('\\040', ' ')
        result[mount] = (fields[2], after[1])
    return result


def verified_partition(mount, mount_entry, ident):
    """Fail closed unless mountinfo, sysfs and ATA by-id agree on one partition.

    sdX names are resolved fresh on every refresh, never stored as identities.
    No block device is opened. A label or directory name alone is insufficient.
    """
    major_minor, source = mount_entry
    if not re.fullmatch(r'/dev/[a-zA-Z0-9]+', source):
        return False, 'unexpected mount source'
    try:
        # Verify the directory really is this mounted device, not a symlink.
        if mount.is_symlink() or not mount.is_dir():
            return False, 'invalid archive mount directory'
        stat = os.stat(mount)
        actual = f'{os.major(stat.st_dev)}:{os.minor(stat.st_dev)}'
        if actual != major_minor:
            return False, 'mount device number mismatch'
        # sysfs independently maps the mount device number to its *current*
        # kernel partition name; it does not depend on persistent sdX names.
        sys_partition = pathlib.Path('/sys/dev/block') / major_minor
        if not sys_partition.exists():
            return False, 'kernel device identity unavailable'
        info = {}
        for line in (sys_partition / 'uevent').read_text().splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                info[k] = v
        part_name = info.get('DEVNAME', '')
        if info.get('DEVTYPE') != 'partition' or not re.fullmatch(r'[a-zA-Z0-9]+', part_name):
            return False, 'kernel device is not a partition'
        if source != '/dev/' + part_name:
            return False, 'mount source disagrees with kernel partition'
        # Require one exact ATA model/serial ID pointing at this partition.
        # The target text can be ../../sdk1 today and ../../sdl1 tomorrow.
        matches = []
        for link in DISK_BY_ID.glob('ata-*-part*'):
            if link.name.rsplit('-part', 1)[0] != 'ata-' + ident:
                continue
            target = os.readlink(link)
            matches.append(pathlib.PurePosixPath(target).name == part_name)
        if len(matches) != 1 or not matches[0]:
            return False, 'hardware serial/partition mismatch or ambiguous identity'
        return True, 'verified'
    except (OSError, ValueError) as exc:
        return False, f'identity unavailable ({exc})'


def collect_storage_snapshots(parsed):
    messages, candidates = [], []
    if not ARCHIVE_MOUNTS.is_dir() or not DISK_BY_ID.is_dir():
        return [], ['Storage snapshots skipped: archive mounts or hardware identifiers unavailable']
    mounts = mounted_sources()
    for data, _, _, _ in parsed:
        ident = data['device_id']
        serial, model = data.get('serial'), data.get('model')
        if not serial or not model or not re.fullmatch(r'[A-Za-z0-9_.-]+', ident):
            messages.append(f'{ident}: skipped (incomplete registered identity)')
            continue
        if ident != model.replace(' ', '_') + '_' + serial:
            messages.append(f'{ident}: skipped (registration identity inconsistent)')
            continue
        mount = ARCHIVE_MOUNTS / ident
        entry = mounts.get(str(mount))
        if entry is None:
            messages.append(f'{ident}: offline or not independently mounted; snapshot retained')
            continue
        verified, reason = verified_partition(mount, entry, ident)
        if not verified:
            messages.append(f'{ident}: skipped ({reason}); snapshot retained')
            continue
        try:
            stats = os.statvfs(mount)
            total = stats.f_blocks * stats.f_frsize
            used = (stats.f_blocks - stats.f_bfree) * stats.f_frsize
            available = stats.f_bavail * stats.f_frsize
            if total <= 0 or used < 0 or available < 0 or used > total or available > total:
                raise ValueError('invalid filesystem statistics')
            candidates.append((ident, used, available, datetime.datetime.now(UTC).isoformat(timespec='seconds')))
            messages.append(f'{ident}: verified serial {serial}; storage snapshot recorded')
        except (OSError, ValueError) as exc:
            messages.append(f'{ident}: skipped ({exc}); snapshot retained')
    return candidates, messages

def backup():
    BACKUPS.mkdir(parents=True,exist_ok=True)
    stamp=datetime.datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')
    target=BACKUPS/f'cold_storage_{stamp}.db'
    with LOCK:
        with closing(connect()) as source, closing(sqlite3.connect(str(target))) as dest:
            source.backup(dest)
    return target

def esc(value): return html.escape(str(value or ''))
def parse_stamp(value):
    dt=datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt

def when(value):
    if not value: return 'Never'
    try:
        return parse_stamp(value).astimezone(LOCAL_TZ).strftime('%b %d, %Y · %I:%M:%S %p %Z')
    except (ValueError, TypeError):
        return str(value)

def due(row):
    if not row['last_pass']: return 'Never verified'
    try:
        # Schedule by the local calendar date of the successful verification.
        last_local=parse_stamp(row['last_pass']).astimezone(LOCAL_TZ)
        due_date=last_local.date()+datetime.timedelta(days=row['interval_days'] or 180)
        return due_date.isoformat()+(' · OVERDUE' if due_date<datetime.datetime.now(LOCAL_TZ).date() else '')
    except (ValueError, TypeError): return 'Unknown'

CSS='''<style>body{margin:0;background:#f4f6f9;color:#17243a;font:15px system-ui,-apple-system,Segoe UI,sans-serif}header{background:#142a44;color:white;padding:23px max(22px,calc((100% - 1150px)/2))}header h1{margin:0;font-size:26px}header small{color:#b7c7d8}main{max-width:1150px;margin:28px auto;padding:0 20px}nav{display:flex;gap:12px;margin:18px 0;flex-wrap:wrap}a{color:#1766b2;text-decoration:none}nav a{background:white;padding:10px 15px;border-radius:8px;border:1px solid #dce3ed}.panel{background:white;border:1px solid #dce3ed;border-radius:12px;padding:20px;margin:18px 0;overflow:auto}h2{font-size:19px;margin:0 0 14px}.muted{color:#667589}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.metric{background:white;padding:19px;border:1px solid #dce3ed;border-radius:12px}.metric b{display:block;font-size:27px;margin-top:8px}table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:11px 10px;border-bottom:1px solid #e9edf3;vertical-align:top}th{color:#52647b}input{padding:11px;border:1px solid #bdcad9;border-radius:7px;width:min(500px,80%)}button{background:#1766b2;border:0;color:white;padding:11px 15px;border-radius:7px;cursor:pointer}code{overflow-wrap:anywhere}.warn{color:#9c5b08;font-weight:650}.bad{color:#b52d3d;font-weight:650}.good{color:#217548;font-weight:650}footer{color:#667589;margin:28px 0}.filetree{list-style:none;padding-left:24px;margin:6px 0}.filetree li{padding:5px 0;overflow-wrap:anywhere}.filetree a{font-weight:600}.driveicon{display:inline-block;width:19px;height:16px;vertical-align:-3px;margin-right:6px;color:#3476ad}.driveicon svg{width:100%;height:100%}.drive-tag{font-size:12px;color:#52647b;margin-left:8px}.index-file{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}.brand{display:flex;align-items:center;gap:14px}.brand img{width:52px;height:52px;border-radius:10px}.breadcrumb{overflow-wrap:anywhere}
:root{color-scheme:light;--bg:#f4f6f9;--fg:#17243a;--surface:#fff;--border:#dce3ed;--subtle:#667589;--accent:#1766b2;--header:#142a44;--track:#e5eaf0;--headtext:#52647b}
:root[data-theme="dark"]{color-scheme:dark;--bg:#111923;--fg:#e9f0f8;--surface:#1c2938;--border:#34485c;--subtle:#a8b9ca;--accent:#78b9f7;--header:#101d2b;--track:#35475a;--headtext:#bbcbdb}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--bg:#111923;--fg:#e9f0f8;--surface:#1c2938;--border:#34485c;--subtle:#a8b9ca;--accent:#78b9f7;--header:#101d2b;--track:#35475a;--headtext:#bbcbdb}}
body{background:var(--bg);color:var(--fg)}header{background:var(--header)}a{color:var(--accent)}nav a,.panel,.metric{background:var(--surface);border-color:var(--border)}.muted,footer{color:var(--subtle)}th,.drive-tag{color:var(--headtext)}th,td{border-color:var(--border)}input,select{background:var(--surface);color:var(--fg);border:1px solid var(--border)}.theme-control{margin-left:auto;display:flex;align-items:center;gap:8px;color:#dce9f7}.theme-control select{padding:7px;border-radius:7px;min-width:95px}.brand{flex-wrap:wrap}.storage-stats{margin-top:16px}.storage-card{border:1px solid var(--border);background:var(--surface);border-radius:10px;padding:16px;margin:12px 0}.storage-card h3{margin:0 0 6px;font-size:16px;overflow-wrap:anywhere}.storage-bar{height:11px;border-radius:99px;background:var(--track);overflow:hidden;margin:10px 0}.storage-fill{height:100%;background:#238c9b}.storage-meta{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}.storage-note{font-size:13px;color:var(--subtle)}.metric b{overflow-wrap:anywhere}.metric small{display:block;color:var(--subtle);margin-top:6px}footer{display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px}button{background:#1766b2}button:hover{filter:brightness(1.08)}
</style>'''

def disk_icon():
    return ('<span class="driveicon" aria-label="Hard drive"><svg viewBox="0 0 24 24" fill="none" '
            'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" '
            'aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="3"/>'
            '<path d="M3 14h18"/><circle cx="7" cy="17" r=".7" fill="currentColor"/></svg></span>')

def human_bytes(value):
    if value is None: return '—'
    value=int(value)
    if value>=10**12: return f'{value/10**12:,.2f} TB'
    if value>=10**9: return f'{value/10**9:,.2f} GB'
    return f'{value:,} bytes'

def storage_overview(db, drives):
    snapshots={r['drive_id']:r for r in db.execute('SELECT * FROM storage_snapshots').fetchall()}
    total_capacity=sum(int(r['capacity']) for r in drives if r['capacity'] is not None and int(r['capacity'])>=0)
    known=[(r,snapshots[r['id']]) for r in drives if r['id'] in snapshots and r['capacity'] is not None and 0<=snapshots[r['id']]['used_bytes']<=r['capacity'] and 0<=snapshots[r['id']]['available_bytes']<=r['capacity']]
    used=sum(x['used_bytes'] for _,x in known)
    available=sum(x['available_bytes'] for _,x in known)
    complete=len(known)==len(drives) and bool(drives)
    scope='All registered drives' if complete else f'{len(known)} of {len(drives)} drives with snapshots'
    body='<section class="panel"><h2>Archive Storage Overview</h2><p class="muted">Capacity is based on registered drive metadata. Usage is based on the latest recorded snapshots, not live disk scans.</p>'
    body+='<div class="grid storage-stats">'
    body+=f'<div class="metric">Total registered capacity<b>{human_bytes(total_capacity)}</b><small>{len(drives)} registered drive(s)</small></div>'
    body+=f'<div class="metric">Recorded used<b>{human_bytes(used) if known else "—"}</b><small>{esc(scope)}</small></div>'
    body+=f'<div class="metric">Recorded available<b>{human_bytes(available) if known else "—"}</b><small>{esc(scope)}</small></div></div>'
    if not complete: body+='<p class="storage-note">Usage totals are incomplete; drives without snapshots are excluded. Available space is not estimated from capacity alone.</p>'
    for r in drives:
        ident=r['id'];cap=r['capacity'];snap=snapshots.get(ident)
        valid=bool(snap and cap is not None and cap>0 and 0<=snap['used_bytes']<=cap and 0<=snap['available_bytes']<=cap)
        body+='<div class="storage-card">'
        body+=f'<h3><a href="/drive?id={urllib.parse.quote(ident)}">{disk_icon()}{esc(r["model"] or ident)}</a></h3>'
        body+=f'<div class="storage-note">Serial: {esc(r["serial"] or "Unknown")} · <a href="/files?drive={urllib.parse.quote(ident)}">Browse files →</a></div>'
        body+=f'<div class="storage-meta"><span>Capacity: <b>{human_bytes(cap)}</b></span><span>{"Used: "+human_bytes(snap["used_bytes"]) if valid else "Usage unavailable"}</span></div>'
        if valid:
            pct=100*snap['used_bytes']/cap
            body+=f'<div class="storage-bar" role="progressbar" aria-label="Recorded used capacity" aria-valuenow="{pct:.1f}" aria-valuemin="0" aria-valuemax="100"><div class="storage-fill" style="width:{pct:.2f}%"></div></div>'
            body+=f'<div class="storage-note">{pct:.1f}% recorded used · {human_bytes(snap["available_bytes"])} recorded available · Snapshot: {esc(when(snap["captured_at"]))}</div>'
        else:body+='<div class="storage-bar" aria-label="Usage unavailable"></div><div class="storage-note">Storage snapshot not yet recorded</div>'
        body+='</div>'
    if not drives:body+='<p class="muted">No drives registered yet.</p>'
    return body+'</section>'

def layout(body):
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" '
            'content="width=device-width,initial-scale=1"><title>Cold Storage — Offline archive catalog</title>'
            '<link rel="icon" type="image/png" href="/assets/favicon-32.png">'+CSS+
            '<header><div class="brand"><img src="/assets/dashboard-icon.png" alt="" width="52" height="52">'
            '<div><h1>Cold Storage</h1><small>Offline archive catalog</small></div><label class="theme-control" for="theme">Theme <select id="theme" aria-label="Color theme"><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select></label></div></header>'
            '<main><nav><a href="/files">'+disk_icon()+'Archive Drives</a>'
            '<a href="/index">Master Index</a><a href="/">Overview</a>'
            '<a href="/history">Verification history</a></nav>'+body+
            '<footer><span>Read-only archive metadata · Catalog refresh never verifies files</span><span>Cold Storage v'+esc(APP_VERSION)+'</span></footer></main><script src="/assets/theme.js" defer></script></html>')

def master_index(db, q):
    term=q.get('q',[''])[0][:300].strip()
    folder=q.get('folder',[''])[0][:2000].strip('/')
    if folder and (folder.startswith('.') or any(x in ('','.', '..') for x in folder.split('/'))):
        return '<section class="panel">Invalid folder</section>',400
    rows=db.execute('SELECT drive_id,path FROM files ORDER BY path COLLATE NOCASE,drive_id').fetchall()
    tree={'dirs':{},'files':[]}
    for r in rows:
        parts=r['path'].split('/')
        if not parts or not parts[0]:continue
        if term and term.casefold() not in r['path'].casefold() and term.casefold() not in r['drive_id'].casefold():continue
        node=tree
        for part in parts[:-1]:
            node=node['dirs'].setdefault(part,{'dirs':{},'files':[]})
        node['files'].append((parts[-1],r['drive_id'],r['path']))
    def link(path):return '/index?'+urllib.parse.urlencode({'folder':path,'q':''})
    body='<section class="panel"><h2>Master Index · All archive drives</h2>'
    body+='<p class="muted">Matching folders are combined across drives. Each file identifies its physical archive drive, including duplicate filenames.</p>'
    body+='<form action="/index" method="get"><input name="q" value="'+esc(term)+'" placeholder="Search every archive drive..."> <button>Search</button></form>'
    if term:
        body+='<p class="muted">Showing files whose paths or drive IDs match your search.</p>'
    elif folder:
        parent='/'.join(folder.split('/')[:-1])
        body+='<p class="breadcrumb"><a href="'+esc(link(parent))+'">← Parent folder</a> / '+esc(folder)+'</p>'
    else:body+='<p class="muted">Browse the combined folder structure below.</p>'
    if folder and not term:
        for part in folder.split('/'):
            tree=tree['dirs'].get(part)
            if tree is None:break
    if tree is None:return body+'<p>Folder not found.</p></section>',404
    def render(node,prefix='',depth=0):
        if depth>60:return ''
        result='<ul class="filetree">'
        for name,child in sorted(node['dirs'].items(),key=lambda x:x[0].casefold()):
            path=(prefix+'/'+name).strip('/')
            result+='<li>📁 <a href="'+esc(link(path))+'">'+esc(name)+'</a>'
            if term:result+=render(child,path,depth+1)
            result+='</li>'
        for name,drive,path in sorted(node['files'],key=lambda x:(x[0].casefold(),x[1])):
            result+='<li class="index-file">📄 <span title="'+esc(path)+'">'+esc(name)+'</span> <span class="drive-tag">'+disk_icon()+esc(drive)+'</span></li>'
        return result+'</ul>'
    body+=render(tree,folder if not term else '')
    if not tree['dirs'] and not tree['files']:body+='<p>No matching files found.</p>'
    return body+'</section>',200

class Handler(BaseHTTPRequestHandler):
    def asset(self,name):
        if name not in ('dashboard-icon.png','favicon-32.png','favicon-16.png','theme.js'):
            self.send_error(404);return
        try:data=(pathlib.Path(__file__).parent/'assets'/name).read_bytes()
        except OSError:self.send_error(404);return
        self.send_response(200);self.send_header('Content-Type','application/javascript; charset=utf-8' if name=='theme.js' else 'image/png')
        self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','public, max-age=86400')
        self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(data)
    def respond(self,content,code=200):
        payload=layout(content).encode('utf-8')
        self.send_response(code);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Length',str(len(payload)));self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; form-action 'self'; img-src 'self'; base-uri 'none'");self.end_headers();self.wfile.write(payload)
    def do_GET(self):
        route=urllib.parse.urlsplit(self.path); q=urllib.parse.parse_qs(route.query)
        if route.path.startswith('/assets/'):
            self.asset(route.path.removeprefix('/assets/'));return
        with closing(connect()) as db:
            if route.path=='/index':
                body,status=master_index(db,q);self.respond(body,status);return
            if route.path=='/':
                drives=db.execute('SELECT * FROM drives ORDER BY id').fetchall()
                total=sum(r['file_count'] for r in drives)
                updated=db.execute("SELECT value FROM meta WHERE key='last_refresh'").fetchone()
                body=f'<div class="grid"><div class="metric">Registered drives<b>{len(drives)}</b></div><div class="metric">Cataloged files<b>{total:,}</b></div><div class="metric">Catalog refreshed<b style="font-size:15px">{esc(when(updated[0]) if updated else "Never")}</b></div></div>'
                body+=storage_overview(db,drives)
                body+='<section class="panel"><h2>Manual catalog actions</h2><p class="muted">Refresh imports registered filenames and integrity logs, and records space statistics for identity-verified mounted archive drives. It never reads archived file contents or runs SHA-256 verification.</p><form method="post" action="/refresh"><button>Refresh catalog</button></form><p><form method="post" action="/backup"><button>Back up SQLite database to array</button></form></p></section>'
                body+='<section class="panel"><h2>'+disk_icon()+'Archive drives</h2><table><tr><th>Drive</th><th>Files</th><th>Last successful check</th><th>Next due</th><th>Attention</th></tr>'
                for r in drives:
                    attention=[]
                    if r['pending']: attention.append('New registrations since last PASS')
                    if r['last_result'] and r['last_result']!='PASS': attention.append('Latest verification: '+r['last_result'])
                    if not r['last_pass']: attention.append('No successful full verification')
                    issue_count=db.execute('SELECT COUNT(*) FROM issues WHERE drive_id=?',(r['id'],)).fetchone()[0]
                    if issue_count: attention.append(f'{issue_count} historical issue entries')
                    body+=f'<tr><td><a href="/drive?id={urllib.parse.quote(r["id"])}"><code>{esc(r["id"])}</code></a><div class="muted">{esc(r["model"])}</div></td><td>{r["file_count"]}</td><td>{esc(when(r["last_pass"]))}</td><td>{esc(due(r))}</td><td class="{ "warn" if attention else "good" }">{esc("; ".join(attention) if attention else "No flags")}</td></tr>'
                body+='</table></section>'
                self.respond(body);return
            if route.path=='/files':
                term=q.get('q',[''])[0][:300].strip()
                drive=q.get('drive',[''])[0][:200]
                folder=q.get('folder',[''])[0][:2000].strip('/')
                valid_drives={r['id'] for r in db.execute('SELECT id FROM drives')}
                if drive and drive not in valid_drives:
                    self.respond('<section class="panel">Drive not found</section>',404);return
                if folder and (folder.startswith('.') or any(x in ('','.', '..') for x in folder.split('/'))):
                    self.respond('<section class="panel">Invalid folder</section>',400);return
                args=[];sql='SELECT drive_id,path FROM files WHERE 1=1'
                if drive:sql+=' AND drive_id=?';args.append(drive)
                # Browse a folder without a search, or show matching files with their parent directories.
                if term:
                    sql+=" AND path LIKE ? ESCAPE '\\' COLLATE NOCASE"
                    args.append('%'+term.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%')
                elif folder:
                    sql+=" AND path LIKE ? ESCAPE '\\'"
                    args.append(folder.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'/%')
                rows=db.execute(sql+' ORDER BY drive_id,path',args).fetchall()
                def url(d='',f='',search=''):
                    return '/files?'+urllib.parse.urlencode({'drive':d,'folder':f,'q':search})
                body='<section class="panel"><h2>Browse offline files</h2><form method="get" action="/files"><input name="q" placeholder="Search filename or folder..." value="'+esc(term)+'"><input type="hidden" name="drive" value="'+esc(drive)+'"> <button>Search</button></form>'
                if term:
                    body+='<p class="muted">'+str(len(rows))+' matching files. Showing folders containing those matches.</p>'
                else:
                    body+='<p class="muted">Folders first, followed by files. Select a folder to open it.</p>'
                if drive:body+='<p><a href="'+esc(url())+'">All drives</a> · <a href="'+esc(url(drive))+'">Drive root</a></p>'
                if folder and not term:
                    parent='/'.join(folder.split('/')[:-1]);body+='<p><a href="'+esc(url(drive,parent))+'">← Parent folder</a> / '+esc(folder)+'</p>'
                if not drive:
                    body+='<h3>Archive drives</h3><ul class="filetree">'
                    for d in sorted(valid_drives):
                        count=sum(1 for r in rows if r['drive_id']==d)
                        if term and not count: continue
                        body+='<li>'+disk_icon()+' <a href="'+esc(url(d,'',term))+'">'+esc(d)+'</a> <span class="muted">('+str(count)+' files'+(' matching' if term else '')+')</span></li>'
                    body+='</ul>'
                    if term and not rows: body+='<p>No matching files found.</p>'
                    # Do not render a drive's root folders until that drive is selected.
                    self.respond(body+'</section>');return
                # Construct the hierarchy from cataloged file paths only; archive disks remain offline.
                tree={}
                for r in rows:
                    d=r['drive_id'];parts=r['path'].removeprefix('./').strip('/').split('/')
                    if not parts or not parts[0]:continue
                    current=tree.setdefault(d,{'dirs':{},'files':[]})
                    for part in parts[:-1]:current=current['dirs'].setdefault(part,{'dirs':{},'files':[]})
                    current['files'].append(parts[-1])
                def render(node, d, prefix='', depth=0):
                    if depth>60:return ''
                    result='<ul class="filetree">'
                    for name, child in sorted(node['dirs'].items(),key=lambda x:x[0].casefold()):
                        path=(prefix+'/'+name).strip('/')
                        result+='<li>📁 <a href="'+esc(url(d,path, '' if not term else term))+'">'+esc(name)+'</a>'
                        if term:result+=render(child,d,path,depth+1)
                        result+='</li>'
                    for name in sorted(node['files'],key=str.casefold):
                        result+='<li>📄 <span title="'+esc(prefix+'/'+name)+'">'+esc(name)+'</span></li>'
                    return result+'</ul>'
                for d in sorted(tree):
                    node=tree[d]
                    if folder and not term:
                        for part in folder.split('/'):
                            node=node['dirs'].get(part)
                            if node is None:break
                    if node is None:continue
                    body+='<h3>'+disk_icon()+esc(d)+'</h3>'+render(node,d,folder if not term else '')
                if not rows:body+='<p>No matching files found.</p>'
                self.respond(body+'</section>');return
            if route.path=='/drive':
                ident=q.get('id',[''])[0]
                r=db.execute('SELECT * FROM drives WHERE id=?',(ident,)).fetchone()
                if not r:self.respond('<div class="panel">Drive not found</div>',404);return
                runs=db.execute('SELECT * FROM runs WHERE drive_id=? ORDER BY seq DESC LIMIT 20',(ident,)).fetchall()
                body=f'<section class="panel"><h2>{esc(ident)}</h2><p>Model: {esc(r["model"])} · Serial: {esc(r["serial"])} · Capacity: {r["capacity"]:,} bytes</p><p>Cataloged files: <b>{r["file_count"]}</b> · Last PASS: <b>{esc(when(r["last_pass"]))}</b> · Next due: <b>{esc(due(r))}</b></p><p class="{ "warn" if r["pending"] else "muted" }">{ "New registrations since last successful full verification" if r["pending"] else "No new registration flag" }</p><p><a href="/files?drive={urllib.parse.quote(ident)}">Browse this drive’s files →</a></p></section><section class="panel"><h2>Recent operations</h2><table><tr><th>Local Time</th><th>Action</th><th>Result</th><th>Tracked</th><th>Delta</th><th>Issues</th></tr>'
                for x in runs:body+=f'<tr><td>{esc(when(x["stamp"]))}</td><td>{esc(x["action"])}</td><td>{esc(x["result"])}</td><td>{x["tracked"]}</td><td>{x["delta"]}</td><td>{x["issues"]}</td></tr>'
                issues=db.execute('SELECT raw FROM issues WHERE drive_id=? ORDER BY seq DESC LIMIT 50',(ident,)).fetchall()
                body+='</table></section><section class="panel"><h2>Historical issue records</h2>'
                body+=('<p>No issue records found.</p>' if not issues else '<ul>'+''.join('<li><code>'+esc(x['raw'])+'</code></li>' for x in issues)+'</ul>')
                self.respond(body+'</section>');return
            if route.path=='/history':
                rows=db.execute('SELECT * FROM runs ORDER BY stamp DESC LIMIT 200').fetchall()
                body='<section class="panel"><h2>Verification and registration history</h2><table><tr><th>Local Time</th><th>Drive</th><th>Action</th><th>Result</th><th>Issues</th></tr>'
                for r in rows:body+=f'<tr><td>{esc(when(r["stamp"]))}</td><td>{esc(r["drive_id"])}</td><td>{esc(r["action"])}</td><td>{esc(r["result"])}</td><td>{r["issues"]}</td></tr>'
                self.respond(body+'</table></section>');return
        self.respond('<div class="panel">Page not found</div>',404)
    def do_POST(self):
        if self.path not in ('/refresh','/backup'):
            self.respond('<div class="panel">Not found</div>',404);return
        try:
            if self.path=='/refresh':
                count,errors=refresh()
                if errors:self.respond('<section class="panel"><h2>Refresh stopped</h2><p>No catalog changes were made.</p><pre>'+esc('\n'.join(errors))+'</pre></section>',500);return
                with closing(connect()) as db:
                    report=db.execute("SELECT value FROM meta WHERE key='storage_refresh_report'").fetchone()
                details=json.loads(report[0]) if report else []
                msg=f'Imported metadata from {count} registered drive(s).'
                if details: msg+='\n'+'\n'.join(details)
            else:
                path=backup();msg='Consistent SQLite backup created: '+str(path)
            self.respond('<section class="panel"><h2>Completed</h2><pre style="white-space:pre-wrap">'+esc(msg)+'</pre><p><a href="/">Return to overview</a></p></section>')
        except Exception as exc:
            self.respond('<section class="panel"><h2>Operation failed</h2><pre>'+esc(exc)+'</pre></section>',500)

if __name__=='__main__':
    init()
    print('cold_storage listening on port',PORT,flush=True)
    ThreadingHTTPServer(('0.0.0.0',PORT),Handler).serve_forever()

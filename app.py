import os,sqlite3,hashlib,hmac,secrets,time,re,uuid,mimetypes,json
from pathlib import Path
from contextlib import contextmanager
from fastapi import FastAPI,HTTPException,Request,Response,Depends,UploadFile,File
from fastapi.responses import FileResponse,JSONResponse
from pydantic import BaseModel,Field

DB=os.getenv('DATABASE_PATH',str(Path(__file__).with_name('signpilot.db')))
SECURE=os.getenv('COOKIE_SECURE','false').lower()=='true'
app=FastAPI(title='SignPilot V5',docs_url=None,redoc_url=None)
ROLES={'admin','sales','production','stock_controller','viewer'}
STAGES=['Quote','Design','Awaiting Approval','Approved','Printing','Ready','Completed & Collected','Cancelled','New','Finishing','Completed']
ACTIVE_STAGES={'Quote','Design','Awaiting Approval','Approved','Printing','Ready','Completed & Collected','Cancelled'}
@contextmanager
def conn():
    Path(DB).parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(DB,timeout=20)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA journal_mode=WAL')
    try:
        yield db
        db.commit()
    finally: db.close()
def pw_hash(p):
    salt=secrets.token_bytes(16)
    return salt.hex()+':'+hashlib.pbkdf2_hmac('sha256',p.encode(),salt,300000).hex()
def pw_check(p,stored):
    try:
        salt,digest=stored.split(':')
        return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(salt),300000),bytes.fromhex(digest))
    except Exception:return False
with conn() as db:
    db.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires INTEGER NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS customers(id INTEGER PRIMARY KEY,name TEXT NOT NULL,phone TEXT DEFAULT '',email TEXT DEFAULT '',created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY,title TEXT NOT NULL,customer_id INTEGER,rep_id INTEGER NOT NULL,assigned_id INTEGER,status TEXT NOT NULL,description TEXT DEFAULT '',width_mm REAL DEFAULT 0,height_mm REAL DEFAULT 0,quantity INTEGER DEFAULT 1,price REAL DEFAULT 0,due_date TEXT DEFAULT '',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,FOREIGN KEY(customer_id) REFERENCES customers(id),FOREIGN KEY(rep_id) REFERENCES users(id),FOREIGN KEY(assigned_id) REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,job_id INTEGER NOT NULL,user_id INTEGER NOT NULL,action TEXT NOT NULL,at INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_jobs_updated ON jobs(updated_at);
    ''')
    # Additive migration: preserve all existing users, customers, jobs and audit history.
    existing={r['name'] for r in db.execute('PRAGMA table_info(jobs)')}
    for field,typ in [('material','TEXT NOT NULL DEFAULT ""'),('finish','TEXT NOT NULL DEFAULT ""'),('production_instructions','TEXT NOT NULL DEFAULT ""')]:
        if field not in existing:db.execute(f'ALTER TABLE jobs ADD COLUMN {field} {typ}')
    db.execute("""CREATE TABLE IF NOT EXISTS attachments(id INTEGER PRIMARY KEY,job_id INTEGER NOT NULL,user_id INTEGER NOT NULL,original_name TEXT NOT NULL,stored_name TEXT NOT NULL,content_type TEXT NOT NULL,size_bytes INTEGER NOT NULL,created_at INTEGER NOT NULL,FOREIGN KEY(job_id) REFERENCES jobs(id),FOREIGN KEY(user_id) REFERENCES users(id))""")
    db.execute('CREATE INDEX IF NOT EXISTS idx_attachments_job ON attachments(job_id)')
    # Customer events cannot use audit.job_id because that column is NOT NULL.
    # Use a dedicated, tenant-scoped table without changing existing audit records.
    db.execute('''CREATE TABLE IF NOT EXISTS customer_audit(
        id INTEGER PRIMARY KEY, business_id INTEGER NOT NULL, customer_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL, action TEXT NOT NULL, at INTEGER NOT NULL
    )''')
    db.execute('CREATE INDEX IF NOT EXISTS idx_customer_audit_business ON customer_audit(business_id,at)')
    if not db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
        email=os.getenv('ADMIN_EMAIL','admin@signpilot.local').lower().strip()
        password=os.getenv('ADMIN_PASSWORD','')
        if len(password)<12:
            raise RuntimeError('Set ADMIN_PASSWORD (minimum 12 characters) before first start')
        db.execute('INSERT INTO users(email,name,password,role) VALUES(?,?,?,?)',(email,'Administrator',pw_hash(password),'admin'))

# Per-user appearance settings; images are private to the authenticated owner.
with conn() as db:
    db.execute("""CREATE TABLE IF NOT EXISTS appearance(user_id INTEGER PRIMARY KEY,theme TEXT NOT NULL DEFAULT 'dark',accent TEXT NOT NULL DEFAULT '#3b82f6',overlay INTEGER NOT NULL DEFAULT 65,blur INTEGER NOT NULL DEFAULT 0,fit TEXT NOT NULL DEFAULT 'cover',image_name TEXT NOT NULL DEFAULT '',FOREIGN KEY(user_id) REFERENCES users(id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS proof_reviews(id INTEGER PRIMARY KEY,job_id INTEGER NOT NULL,user_id INTEGER NOT NULL,decision TEXT NOT NULL,note TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,FOREIGN KEY(job_id) REFERENCES jobs(id),FOREIGN KEY(user_id) REFERENCES users(id))""")

class Login(BaseModel):email:str;password:str
class UserIn(BaseModel):email:str;name:str;password:str;role:str='sales'
class CustomerIn(BaseModel):name:str;phone:str='';email:str=''
class JobIn(BaseModel):title:str;customer_id:int|None=None;rep_id:int|None=None;assigned_id:int|None=None;status:str='Quote';description:str='';width_mm:float=0;height_mm:float=0;quantity:int=1;price:float=0;due_date:str='';material:str='';finish:str='';production_instructions:str=''
class JobPatch(BaseModel):materials:list[dict]|None=None;title:str|None=None;customer_id:int|None=None;rep_id:int|None=None;assigned_id:int|None=None;status:str|None=None;description:str|None=None;price:float|None=None;due_date:str|None=None;width_mm:float|None=None;height_mm:float|None=None;quantity:int|None=None;material:str|None=None;finish:str|None=None;production_instructions:str|None=None

def current(request:Request):
    token=request.cookies.get('sp_session','')
    if not token:raise HTTPException(401,'Please sign in')
    with conn() as db:
        u=db.execute('SELECT u.id,u.email,u.name,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>? AND u.active=1',(hashlib.sha256(token.encode()).hexdigest(),int(time.time()))).fetchone()
    if not u:raise HTTPException(401,'Session expired')
    account=dict(u)
    with conn() as db:
        memberships=db.execute('SELECT business_id,role FROM business_memberships WHERE user_id=?',(account['id'],)).fetchall()
    if len(memberships)!=1:raise HTTPException(403,'Business account not configured')
    account['business_id']=memberships[0]['business_id']
    account['role']=memberships[0]['role']
    # A stock controller is restricted at the authentication dependency, not just the UI.
    if account['role']=='stock_controller':
        path=request.url.path
        method=request.method
        allowed=((path=='/api/me' and method=='GET') or
                 (path=='/api/profile' and method in ('GET','PUT')) or
                 (path=='/api/profile/avatar' and method in ('GET','POST','DELETE')) or
                 (path=='/api/logout' and method=='POST') or
                 (path=='/api/stock' and method=='GET') or
                 (re.fullmatch(r'/api/stock/\d+/history',path) and method=='GET') or
                 (re.fullmatch(r'/api/stock/\d+/adjust',path) and method=='POST'))
        if not allowed:raise HTTPException(403,'Stock controllers may access stock quantities only')

    # Viewer may read business information, but never modify business records.
    # Enforce this centrally for every endpoint using current(), including modules.
    if account['role']=='viewer':
        path=request.url.path
        method=request.method
        personal=((path=='/api/profile' and method=='PUT') or
                  (path=='/api/profile/avatar' and method in ('POST','DELETE')) or
                  (path=='/api/logout' and method=='POST') or
                  (path.startswith('/api/appearance') and method in ('PUT','POST','DELETE')))
        if method not in ('GET','HEAD') and not personal:
            raise HTTPException(403,'Viewer access is read-only')

    # Step 3D: entitlement enforcement is OFF by default until end-to-end
    # tenant isolation, billing and account recovery are verified.
    from sm360_access_guard import check_business_access
    check_business_access(conn, account['business_id'])
    return account
def admin(u=Depends(current)):
    if u['role']!='admin':raise HTTPException(403,'Admin access required')
    return u
@app.get('/')
def home():return FileResponse(Path(__file__).parent/'static'/'index.html')
# Update 85: static, self-contained help assistant (no API or data access).
@app.get('/help-assistant.js')
def help_assistant_js():
    return FileResponse(Path(__file__).parent/'static'/'help-assistant.js',media_type='text/javascript',headers={'Cache-Control':'public, max-age=3600','X-Content-Type-Options':'nosniff'})
@app.get('/help-assistant.css')
def help_assistant_css():
    return FileResponse(Path(__file__).parent/'static'/'help-assistant.css',media_type='text/css',headers={'Cache-Control':'public, max-age=3600','X-Content-Type-Options':'nosniff'})
@app.get('/manifest.webmanifest')
def manifest():return FileResponse(Path(__file__).parent/'static'/'manifest.webmanifest',media_type='application/manifest+json',headers={'Cache-Control':'no-cache'})
@app.get('/sw.js')
def service_worker():return FileResponse(Path(__file__).parent/'static'/'sw.js',media_type='text/javascript',headers={'Cache-Control':'no-cache','Service-Worker-Allowed':'/'})
@app.get('/icons/{name}')
def icons(name:str):
    if name not in ('icon-192.png','icon-512.png','signmaster360-logo.png'):raise HTTPException(404)
    return FileResponse(Path(__file__).parent/'static'/'icons'/name,media_type='image/png')
@app.post('/api/voice/transcribe')
async def transcribe_voice(file:UploadFile=File(...),u=Depends(current)):
    key=os.getenv('OPENAI_API_KEY','')
    if not key:raise HTTPException(503,'Voice transcription is not configured. Set OPENAI_API_KEY in Render Environment.')
    allowed={'audio/webm','audio/mp4','audio/mpeg','audio/wav','audio/x-wav','audio/ogg','audio/aac','audio/x-m4a','video/mp4','application/octet-stream'}
    if (file.content_type or '').split(';')[0] not in allowed:raise HTTPException(400,'Unsupported recording type')
    audio=await file.read(10*1024*1024+1)
    if not audio or len(audio)>10*1024*1024:raise HTTPException(413,'Recording must be between 1 byte and 10 MB')
    import urllib.request,urllib.error
    boundary='----SignPilot'+secrets.token_hex(12)
    def field(name,value):return (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n').encode()
    filename='recording.webm'
    mime=(file.content_type or 'audio/webm').split(';')[0]
    ext={'audio/mp4':'m4a','audio/x-m4a':'m4a','video/mp4':'mp4','audio/wav':'wav','audio/x-wav':'wav','audio/mpeg':'mp3','audio/ogg':'ogg','audio/aac':'aac'}.get(mime,'webm')
    filename='recording.'+ext
    body=field('model','gpt-4o-mini-transcribe')+field('prompt','Signage production job in South Africa. Terms: vinyl, Correx, ACM, lamination, eyelets, millimetres, metres, rand. English or Afrikaans.')+(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\nContent-Type: {mime}\r\n\r\n').encode()+audio+b'\r\n'+(f'--{boundary}--\r\n').encode()
    req=urllib.request.Request('https://api.openai.com/v1/audio/transcriptions',data=body,headers={'Authorization':'Bearer '+key,'Content-Type':'multipart/form-data; boundary='+boundary},method='POST')
    try:
        with urllib.request.urlopen(req,timeout=40) as r:result=json.loads(r.read())
    except urllib.error.HTTPError as e:raise HTTPException(502,'Transcription service rejected the recording ('+str(e.code)+'). Check API billing and configuration.')
    except Exception:raise HTTPException(502,'Could not transcribe audio. Please retry or type the job.')
    return {'text':result.get('text','')}
@app.post('/api/login')
def login(data:Login,response:Response):
    with conn() as db:
        u=db.execute('SELECT * FROM users WHERE email=? AND active=1',(data.email.lower().strip(),)).fetchone()
        if not u or not pw_check(data.password,u['password']):raise HTTPException(401,'Invalid credentials')
        token=secrets.token_urlsafe(32)
        db.execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),u['id'],int(time.time())+86400*7))
    response.set_cookie('sp_session',token,httponly=True,secure=SECURE,samesite='lax',max_age=604800)
    return {'ok':True}
@app.post('/api/logout')
def logout(request:Request,response:Response):
    token=request.cookies.get('sp_session','')
    with conn() as db:db.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),))
    response.delete_cookie('sp_session',secure=SECURE,samesite='lax')
    return {'ok':True}
@app.get('/api/me')
def me(u=Depends(current)):return u
@app.get('/api/users')
def users(u=Depends(current)):
    with conn() as db:return [dict(r) for r in db.execute('SELECT u.id,u.name,u.email,m.role,u.active FROM users u JOIN business_memberships m ON m.user_id=u.id WHERE m.business_id=? ORDER BY u.name',(u['business_id'],))]
@app.post('/api/users')
def create_user(data:UserIn,u=Depends(admin)):
    if data.role not in ROLES or len(data.password)<12 or '@' not in data.email or not data.name.strip():raise HTTPException(400,'Check name, email, role and password (12+ characters)')
    try:
        with conn() as db:
            cur=db.execute('INSERT INTO users(email,name,password,role) VALUES(?,?,?,?)',(data.email.lower().strip(),data.name.strip(),pw_hash(data.password),data.role))
            db.execute('INSERT INTO business_memberships(business_id,user_id,role) VALUES(?,?,?)',(u['business_id'],cur.lastrowid,data.role))
            return {'id':cur.lastrowid}
    except sqlite3.IntegrityError:raise HTTPException(409,'Email already exists')
class StaffRoleChange(BaseModel):
    role:str

@app.patch('/api/users/{user_id}/role')
def change_user_role(user_id:int,data:StaffRoleChange,u=Depends(admin)):
    if data.role not in ROLES:raise HTTPException(400,'Invalid staff role')
    with conn() as db:
        member=db.execute('SELECT role FROM business_memberships WHERE business_id=? AND user_id=?',(u['business_id'],user_id)).fetchone()
        if not member:raise HTTPException(404,'Staff member not found in your business')
        if member['role']=='admin' and data.role!='admin':
            count=db.execute("SELECT COUNT(*) FROM business_memberships m JOIN users us ON us.id=m.user_id WHERE m.business_id=? AND m.role='admin' AND us.active=1",(u['business_id'],)).fetchone()[0]
            if count<=1:raise HTTPException(409,'Cannot remove the last active administrator')
        db.execute('UPDATE business_memberships SET role=? WHERE business_id=? AND user_id=?',(data.role,u['business_id'],user_id))
        # Keep legacy role field consistent for single-business accounts.
        db.execute('UPDATE users SET role=? WHERE id=?',(data.role,user_id))
        return {'id':user_id,'role':data.role,'ok':True}

@app.delete('/api/users/{user_id}')
def remove_team_member(user_id:int,u=Depends(admin)):
    if user_id==u['id']:
        raise HTTPException(409,'You cannot remove your own administrator membership')
    with conn() as db:
        # The membership is the only record deleted. Historical users and jobs remain.
        member=db.execute('SELECT role FROM business_memberships WHERE business_id=? AND user_id=?',
                          (u['business_id'],user_id)).fetchone()
        if not member:raise HTTPException(404,'Staff member not found in this business')
        if member['role']=='admin':
            count=db.execute("SELECT COUNT(*) FROM business_memberships m JOIN users us ON us.id=m.user_id WHERE m.business_id=? AND m.role='admin' AND us.active=1",(u['business_id'],)).fetchone()[0]
            if count<=1:raise HTTPException(409,'Cannot remove the last active administrator')
        db.execute('DELETE FROM business_memberships WHERE business_id=? AND user_id=?',
                   (u['business_id'],user_id))
        # Existing sessions are not globally deleted: current() verifies membership
        # on every request, so access to this business ends immediately.
        db.execute("""CREATE TABLE IF NOT EXISTS sm360_team_removal_audit(
            id INTEGER PRIMARY KEY,business_id INTEGER NOT NULL,actor_id INTEGER NOT NULL,
            removed_user_id INTEGER NOT NULL,removed_role TEXT NOT NULL,at INTEGER NOT NULL)""")
        db.execute('INSERT INTO sm360_team_removal_audit(business_id,actor_id,removed_user_id,removed_role,at) VALUES(?,?,?,?,?)',
                   (u['business_id'],u['id'],user_id,member['role'],int(time.time())))
    return {'ok':True,'removed_user_id':user_id}

@app.get('/api/customers')
def customers(u=Depends(current)):
    with conn() as db:return [dict(r) for r in db.execute('SELECT * FROM customers WHERE business_id=? ORDER BY name',(u['business_id'],))]
@app.post('/api/customers')
def create_customer(data:CustomerIn,u=Depends(current)):
    if not data.name.strip():raise HTTPException(400,'Name required')
    with conn() as db:
        cur=db.execute('INSERT INTO customers(name,phone,email,created_at,business_id) VALUES(?,?,?,?,?)',(data.name.strip(),data.phone,data.email,int(time.time()),u['business_id']))
        return {'id':cur.lastrowid}
@app.put('/api/customers/{customer_id}')
def update_customer(customer_id:int,data:CustomerIn,u=Depends(current)):
    if u['role']=='production':raise HTTPException(403,'Production cannot edit customers')
    if not data.name.strip():raise HTTPException(400,'Customer name required')
    with conn() as db:
        if not db.execute('SELECT 1 FROM customers WHERE id=? AND business_id=?',(customer_id,u['business_id'])).fetchone():raise HTTPException(404,'Customer not found')
        db.execute('UPDATE customers SET name=?,phone=?,email=? WHERE id=? AND business_id=?',(data.name.strip(),data.phone.strip(),data.email.strip(),customer_id,u['business_id']))
        db.execute('INSERT INTO customer_audit(business_id,customer_id,user_id,action,at) VALUES(?,?,?,?,?)',(u['business_id'],customer_id,u['id'],'Edited customer',int(time.time())))
    return {'ok':True}
@app.delete('/api/customers/{customer_id}')
def delete_customer(customer_id:int,u=Depends(admin)):
    with conn() as db:
        if not db.execute('SELECT 1 FROM customers WHERE id=? AND business_id=?',(customer_id,u['business_id'])).fetchone():raise HTTPException(404,'Customer not found')
        if db.execute('SELECT 1 FROM jobs WHERE customer_id=? AND business_id=? LIMIT 1',(customer_id,u['business_id'])).fetchone():
            raise HTTPException(409,'This customer has jobs. Reassign those jobs before deleting the customer.')
        db.execute('DELETE FROM customers WHERE id=? AND business_id=?',(customer_id,u['business_id']))
        db.execute('INSERT INTO customer_audit(business_id,customer_id,user_id,action,at) VALUES(?,?,?,?,?)',(u['business_id'],customer_id,u['id'],'Deleted customer',int(time.time())))
    return {'ok':True}
@app.get('/api/jobs')
def jobs(u=Depends(current)):
    with conn() as db:
        return [dict(r) for r in db.execute('''SELECT j.*,c.name customer_name,r.name rep_name,a.name assigned_name FROM jobs j LEFT JOIN customers c ON c.id=j.customer_id JOIN users r ON r.id=j.rep_id LEFT JOIN users a ON a.id=j.assigned_id WHERE j.business_id=? ORDER BY j.updated_at DESC,j.id DESC''',(u['business_id'],))]
def check_job(d):
    if not d.title.strip() or d.status not in ACTIVE_STAGES or d.quantity<1 or min(d.price,d.width_mm,d.height_mm)<0:raise HTTPException(400,'Invalid job fields')
@app.post('/api/jobs')
def create_job(d:JobIn,u=Depends(current)):
    check_job(d)
    if d.assigned_id is None:raise HTTPException(400,'Assigned staff is required')
    if any(len(x)>5000 for x in [d.description,d.production_instructions]) or len(d.material)>200 or len(d.finish)>200:raise HTTPException(400,'Text too long')
    rep=u['id'] if u['role']!='admin' else (d.rep_id or u['id'])
    now=int(time.time())
    try:
        with conn() as db:
            if d.customer_id is not None and not db.execute('SELECT 1 FROM customers WHERE id=? AND business_id=?',(d.customer_id,u['business_id'])).fetchone():raise HTTPException(400,'Invalid customer')
            for uid in (rep,d.assigned_id):
                if uid is not None and not db.execute('SELECT 1 FROM business_memberships WHERE user_id=? AND business_id=? AND role NOT IN (?,?)',(uid,u['business_id'],'viewer','stock_controller')).fetchone():raise HTTPException(400,'Invalid employee')
            cur=db.execute('''INSERT INTO jobs(title,customer_id,rep_id,assigned_id,status,description,width_mm,height_mm,quantity,price,due_date,created_at,updated_at,material,finish,production_instructions,business_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(d.title.strip(),d.customer_id,rep,d.assigned_id,d.status,d.description,d.width_mm,d.height_mm,d.quantity,d.price,d.due_date,now,now,d.material,d.finish,d.production_instructions,u['business_id']))
            db.execute('INSERT INTO audit(job_id,user_id,action,at) VALUES(?,?,?,?)',(cur.lastrowid,u['id'],'Created job',now))
            return {'id':cur.lastrowid}
    except sqlite3.IntegrityError:raise HTTPException(400,'Invalid customer or user')
@app.patch('/api/jobs/{job_id}')
def update_job(job_id:int,d:JobPatch,u=Depends(current)):
    changes=d.model_dump(exclude_unset=True)
    if not changes:raise HTTPException(400,'No changes')
    material_lines=changes.pop('materials',None)
    if material_lines is not None:
        from sm360_job_materials import MaterialLine
        if len(material_lines)>50:raise HTTPException(400,'Maximum 50 materials per job')
        material_lines=[MaterialLine(**line) for line in material_lines]
    if 'status' in changes and changes['status'] not in ACTIVE_STAGES:raise HTTPException(400,'Invalid status')
    if any(k in changes and changes[k] is not None and changes[k]<0 for k in ('price','width_mm','height_mm')) or ('quantity' in changes and (changes['quantity'] is None or changes['quantity']<1)):raise HTTPException(400,'Invalid numeric value')
    for k in ('title','description','material','finish','production_instructions'):
        if k in changes and changes[k] is not None and len(changes[k])>(5000 if k in ('description','production_instructions') else 200):raise HTTPException(400,'Text too long')
    with conn() as db:
        job=db.execute('SELECT * FROM jobs WHERE id=? AND business_id=?',(job_id,u['business_id'])).fetchone()
        if not job:raise HTTPException(404,'Job not found')
        if u['role']=='production' and set(changes)-{'status'}:raise HTTPException(403,'Production can only update status')
        if u['role']=='sales' and job['rep_id']!=u['id'] and set(changes)-{'status'}:raise HTTPException(403,'Only the owning rep or admin can edit job details; all staff may change status')
        if 'customer_id' in changes and changes['customer_id'] is not None and not db.execute('SELECT 1 FROM customers WHERE id=? AND business_id=?',(changes['customer_id'],u['business_id'])).fetchone():raise HTTPException(400,'Invalid customer')
        if 'rep_id' in changes:
            if u['role']!='admin':raise HTTPException(403,'Only administrators can change the sales representative')
            if changes['rep_id'] is None or not db.execute('SELECT 1 FROM business_memberships WHERE user_id=? AND business_id=?',(changes['rep_id'],u['business_id'])).fetchone():raise HTTPException(400,'Invalid sales representative')
        if 'assigned_id' in changes and changes['assigned_id'] is None:raise HTTPException(400,'Assigned staff is required')
        if 'assigned_id' in changes and changes['assigned_id'] is not None and not db.execute('SELECT 1 FROM business_memberships WHERE user_id=? AND business_id=? AND role NOT IN (?,?)',(changes['assigned_id'],u['business_id'],'viewer','stock_controller')).fetchone():raise HTTPException(400,'Invalid employee')
        changes['updated_at']=int(time.time())
        fields=','.join(k+'=?' for k in changes)
        try:db.execute(f'UPDATE jobs SET {fields} WHERE id=? AND business_id=?',(*changes.values(),job_id,u['business_id']))
        except sqlite3.IntegrityError:raise HTTPException(400,'Invalid related record')
        if 'status' in changes or material_lines is not None:
            from sm360_job_materials import reconcile
            reconcile(db,job_id,u['business_id'],u['id'],lines=material_lines,status=changes.get('status'))
        db.execute('INSERT INTO audit(job_id,user_id,action,at) VALUES(?,?,?,?)',(job_id,u['id'],'Updated '+', '.join(changes.keys()),int(time.time())))
    return {'ok':True}
class DeleteJobRequest(BaseModel):
    reason:str=Field(min_length=5,max_length=400)

@app.delete('/api/jobs/{job_id}')
def delete_job(job_id:int,data:DeleteJobRequest,u=Depends(admin)):
    # Archive an immutable snapshot before deleting linked financial records.
    # Only the authenticated administrator of this job's business may do this.
    with conn() as db:
        db.execute('BEGIN IMMEDIATE')
        job=db.execute('SELECT * FROM jobs WHERE id=? AND business_id=?',(job_id,u['business_id'])).fetchone()
        if not job:raise HTTPException(404,'Job not found')
        db.execute("""CREATE TABLE IF NOT EXISTS sm360_deleted_job_archive (
            id INTEGER PRIMARY KEY AUTOINCREMENT,business_id INTEGER NOT NULL,
            job_id INTEGER NOT NULL,deleted_by INTEGER NOT NULL,deleted_at INTEGER NOT NULL,
            reason TEXT NOT NULL,snapshot_json TEXT NOT NULL)""")
        docs=[dict(r) for r in db.execute('SELECT * FROM sm360_documents WHERE job_id=?',(job_id,))] if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='sm360_documents'").fetchone() else []
        docids=[d['id'] for d in docs]
        payments=[]; corrections=[]; invoice_corrections=[]
        if docids:
            placeholders=','.join('?'*len(docids))
            payments=[dict(r) for r in db.execute(f'SELECT * FROM sm360_payments WHERE document_id IN ({placeholders})',docids)]
            paymentids=[r['id'] for r in payments]
            if paymentids and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='sm360_payment_corrections'").fetchone():
                ph=','.join('?'*len(paymentids))
                corrections=[dict(r) for r in db.execute(f'SELECT * FROM sm360_payment_corrections WHERE payment_id IN ({ph})',paymentids)]
                db.execute(f'DELETE FROM sm360_payment_corrections WHERE payment_id IN ({ph})',paymentids)
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='sm360_invoice_value_corrections'").fetchone():
                invoice_corrections=[dict(r) for r in db.execute('SELECT * FROM sm360_invoice_value_corrections WHERE job_id=?',(job_id,))]
                db.execute('DELETE FROM sm360_invoice_value_corrections WHERE job_id=?',(job_id,))
            db.execute(f'DELETE FROM sm360_payments WHERE document_id IN ({placeholders})',docids)
            db.execute('DELETE FROM sm360_documents WHERE job_id=?',(job_id,))
        attachments=[dict(r) for r in db.execute('SELECT * FROM attachments WHERE job_id=?',(job_id,))]
        proofs=[dict(r) for r in db.execute('SELECT * FROM proof_reviews WHERE job_id=?',(job_id,))]
        history=[dict(r) for r in db.execute('SELECT * FROM audit WHERE job_id=?',(job_id,))]
        from sm360_job_materials import reconcile
        material_snapshot=[dict(r) for r in db.execute('SELECT * FROM sm360_job_materials WHERE job_id=? AND business_id=?',(job_id,u['business_id']))]
        snapshot={'materials':material_snapshot,'job':dict(job),'documents':docs,'payments':payments,'payment_corrections':corrections,
                  'invoice_value_corrections':invoice_corrections,'attachments':attachments,
                  'proofs':proofs,'history':history}
        db.execute('INSERT INTO sm360_deleted_job_archive(business_id,job_id,deleted_by,deleted_at,reason,snapshot_json) VALUES(?,?,?,?,?,?)',
                   (u['business_id'],job_id,u['id'],int(time.time()),data.reason.strip(),json.dumps(snapshot)))
        reconcile(db,job_id,u['business_id'],u['id'],delete=True)
        db.execute('DELETE FROM attachments WHERE job_id=?',(job_id,))
        db.execute('DELETE FROM proof_reviews WHERE job_id=?',(job_id,))
        db.execute('DELETE FROM audit WHERE job_id=?',(job_id,))
        try:db.execute('DELETE FROM jobs WHERE id=? AND business_id=?',(job_id,u['business_id']))
        except sqlite3.IntegrityError:raise HTTPException(409,'Job has other linked records and cannot be safely deleted.')
    # Artwork is retained on disk for the audit snapshot, not silently erased.
    return {'ok':True,'archived':True}

@app.get('/api/jobs/{job_id}/history')
def history(job_id:int,u=Depends(current)):
    job_access(job_id,u)
    with conn() as db:return [dict(r) for r in db.execute('SELECT a.action,a.at,usr.name FROM audit a JOIN users usr ON usr.id=a.user_id WHERE a.job_id=? ORDER BY a.id DESC',(job_id,))]
@app.get('/health')
def health():return {'status':'ok'}

# Protected artwork storage: files are never exposed as public static URLs.
UPLOAD_ROOT=Path(os.getenv('UPLOAD_DIR',str(Path(DB).parent/'uploads')))
MAX_UPLOAD=15*1024*1024
ALLOWED={'.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.pdf':'application/pdf','.svg':'image/svg+xml'}
def job_access(job_id,u,edit=False):
    with conn() as db:job=db.execute('SELECT * FROM jobs WHERE id=? AND business_id=?',(job_id,u['business_id'])).fetchone()
    if not job:raise HTTPException(404,'Job not found')
    if edit and (u['role']=='production' or (u['role']=='sales' and job['rep_id']!=u['id'])):raise HTTPException(403,'Not allowed to edit this job')
    return job
@app.get('/api/jobs/{job_id}/attachments')
def list_attachments(job_id:int,u=Depends(current)):
    job_access(job_id,u)
    with conn() as db:return [dict(r) for r in db.execute('SELECT a.id,a.original_name,a.content_type,a.size_bytes,a.created_at,u.name uploaded_by FROM attachments a JOIN users u ON u.id=a.user_id JOIN jobs j ON j.id=a.job_id WHERE a.job_id=? AND j.business_id=? ORDER BY a.id DESC',(job_id,u['business_id']))]
@app.post('/api/jobs/{job_id}/attachments')
async def add_attachment(job_id:int,file:UploadFile=File(...),u=Depends(current)):
    job_access(job_id,u,edit=True)
    name=Path(file.filename or '').name.strip()
    ext=Path(name).suffix.lower()
    if ext not in ALLOWED or not name or len(name)>180:raise HTTPException(400,'Allowed: PNG, JPG, PDF or SVG (max 15 MB)')
    content=await file.read(MAX_UPLOAD+1)
    if len(content)>MAX_UPLOAD:raise HTTPException(413,'File exceeds 15 MB')
    if ext=='.png' and not content.startswith(b'\x89PNG\r\n\x1a\n'):raise HTTPException(400,'Invalid PNG')
    if ext in ('.jpg','.jpeg') and not content.startswith(b'\xff\xd8\xff'):raise HTTPException(400,'Invalid JPEG')
    if ext=='.pdf' and not content.startswith(b'%PDF-'):raise HTTPException(400,'Invalid PDF')
    if ext=='.svg':
        # SVG is active content; disallow for now pending sanitization.
        raise HTTPException(400,'SVG uploads require sanitization; export to PNG or PDF')
    UPLOAD_ROOT.mkdir(parents=True,exist_ok=True)
    stored=uuid.uuid4().hex+ext
    target=UPLOAD_ROOT/stored
    try:
        with open(target,'xb') as f:f.write(content)
        with conn() as db:
            cur=db.execute('INSERT INTO attachments(job_id,user_id,original_name,stored_name,content_type,size_bytes,created_at) VALUES(?,?,?,?,?,?,?)',(job_id,u['id'],name,stored,ALLOWED[ext],len(content),int(time.time())))
            db.execute('INSERT INTO audit(job_id,user_id,action,at) VALUES(?,?,?,?)',(job_id,u['id'],'Uploaded artwork: '+name[:100],int(time.time())))
            return {'id':cur.lastrowid,'name':name}
    except Exception:
        target.unlink(missing_ok=True)
        raise
@app.get('/api/jobs/{job_id}/attachments/{attachment_id}')
def download_attachment(job_id:int,attachment_id:int,u=Depends(current)):
    job_access(job_id,u)
    with conn() as db:r=db.execute('SELECT * FROM attachments WHERE id=? AND job_id=?',(attachment_id,job_id)).fetchone()
    if not r:raise HTTPException(404,'File not found')
    target=UPLOAD_ROOT/r['stored_name']
    if not target.is_file():raise HTTPException(404,'File missing from storage')
    return FileResponse(target,media_type='application/octet-stream',filename=r['original_name'],content_disposition_type='attachment',headers={'X-Content-Type-Options':'nosniff','Cache-Control':'private, no-store'})
@app.delete('/api/jobs/{job_id}/attachments/{attachment_id}')
def delete_attachment(job_id:int,attachment_id:int,u=Depends(current)):
    job_access(job_id,u,edit=True)
    with conn() as db:
        r=db.execute('SELECT * FROM attachments WHERE id=? AND job_id=?',(attachment_id,job_id)).fetchone()
        if not r:raise HTTPException(404,'File not found')
        db.execute('DELETE FROM attachments WHERE id=?',(attachment_id,))
        db.execute('INSERT INTO audit(job_id,user_id,action,at) VALUES(?,?,?,?)',(job_id,u['id'],'Removed artwork: '+r['original_name'][:100],int(time.time())))
    (UPLOAD_ROOT/r['stored_name']).unlink(missing_ok=True)
    return {'ok':True}

# Appearance endpoints are authenticated and scoped to the logged-in user.
class AppearanceIn(BaseModel):
    theme:str='dark'
    accent:str='#3b82f6'
    overlay:int=65
    blur:int=0
    fit:str='cover'
@app.get('/api/appearance')
def get_appearance(u=Depends(current)):
    with conn() as db:
        r=db.execute('SELECT theme,accent,overlay,blur,fit,image_name FROM appearance WHERE user_id=?',(u['id'],)).fetchone()
    return dict(r) if r else {'theme':'dark','accent':'#3b82f6','overlay':65,'blur':0,'fit':'cover','image_name':''}
@app.put('/api/appearance')
def save_appearance(d:AppearanceIn,u=Depends(current)):
    if d.theme not in ('dark','light','gradient','custom') or d.fit not in ('cover','contain','fill') or not 0<=d.overlay<=95 or not 0<=d.blur<=16 or not re.fullmatch(r'#[0-9a-fA-F]{6}',d.accent):raise HTTPException(400,'Invalid appearance setting')
    with conn() as db:
        db.execute("""INSERT INTO appearance(user_id,theme,accent,overlay,blur,fit) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET theme=excluded.theme,accent=excluded.accent,overlay=excluded.overlay,blur=excluded.blur,fit=excluded.fit""",(u['id'],d.theme,d.accent,d.overlay,d.blur,d.fit))
    return {'ok':True}
BG_ROOT=Path(DB).parent/'backgrounds'
@app.post('/api/appearance/image')
async def upload_background(file:UploadFile=File(...),u=Depends(current)):
    ext=Path(file.filename or '').suffix.lower()
    if ext not in ('.jpg','.jpeg','.png','.webp'):raise HTTPException(400,'Use JPG, PNG or WebP')
    content=await file.read(5*1024*1024+1)
    if len(content)>5*1024*1024:raise HTTPException(413,'Maximum 5 MB')
    if not ((ext=='.png' and content.startswith(b'\x89PNG\r\n\x1a\n')) or (ext in ('.jpg','.jpeg') and content.startswith(b'\xff\xd8\xff')) or (ext=='.webp' and content.startswith(b'RIFF') and content[8:12]==b'WEBP')):raise HTTPException(400,'Invalid image')
    BG_ROOT.mkdir(parents=True,exist_ok=True)
    name=uuid.uuid4().hex+ext
    (BG_ROOT/name).write_bytes(content)
    with conn() as db:
        old=db.execute('SELECT image_name FROM appearance WHERE user_id=?',(u['id'],)).fetchone()
        db.execute("""INSERT INTO appearance(user_id,image_name) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET image_name=excluded.image_name""",(u['id'],name))
    if old and old['image_name']:(BG_ROOT/old['image_name']).unlink(missing_ok=True)
    return {'ok':True}
@app.get('/api/appearance/image')
def background_image(u=Depends(current)):
    with conn() as db:r=db.execute('SELECT image_name FROM appearance WHERE user_id=?',(u['id'],)).fetchone()
    if not r or not r['image_name']:raise HTTPException(404,'No background uploaded')
    path=BG_ROOT/r['image_name']
    if not path.is_file():raise HTTPException(404,'Image missing')
    return FileResponse(path,headers={'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'})
@app.delete('/api/appearance/image')
def remove_background(u=Depends(current)):
    with conn() as db:
        old=db.execute('SELECT image_name FROM appearance WHERE user_id=?',(u['id'],)).fetchone()
        db.execute('UPDATE appearance SET image_name=? WHERE user_id=?',('',u['id']))
    if old and old['image_name']:(BG_ROOT/old['image_name']).unlink(missing_ok=True)
    return {'ok':True}
class ProofReview(BaseModel):
    decision:str
    note:str=''
@app.get('/api/jobs/{job_id}/proof-reviews')
def proof_reviews(job_id:int,u=Depends(current)):
    job_access(job_id,u)
    with conn() as db:return [dict(r) for r in db.execute('SELECT p.id,p.decision,p.note,p.created_at,u.name reviewer FROM proof_reviews p JOIN users u ON u.id=p.user_id WHERE job_id=? ORDER BY p.id DESC',(job_id,))]
@app.post('/api/jobs/{job_id}/proof-reviews')
def add_proof_review(job_id:int,d:ProofReview,u=Depends(current)):
    job_access(job_id,u,edit=True)
    if d.decision not in ('Sent for review','Customer approved (recorded by staff)','Changes requested') or len(d.note)>1000:raise HTTPException(400,'Invalid review')
    with conn() as db:
        db.execute('INSERT INTO proof_reviews(job_id,user_id,decision,note,created_at) VALUES(?,?,?,?,?)',(job_id,u['id'],d.decision,d.note,int(time.time())))
        db.execute('INSERT INTO audit(job_id,user_id,action,at) VALUES(?,?,?,?)',(job_id,u['id'],'Proof: '+d.decision,int(time.time())))
    return {'ok':True}

# V6 stage 1: local backup and audit export. Admin only.
from sm360_backup import make_backup, backup_dir, start_local_backup_worker
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask
import tempfile as _sm_tempfile

@app.get('/api/admin/activity')
def global_activity(limit:int=150,u=Depends(admin)):
    limit=max(1,min(limit,500))
    with conn() as db:
        return [dict(r) for r in db.execute("""SELECT a.id,a.job_id,a.action,a.at,u.name actor,j.title job_title
        FROM audit a JOIN users u ON u.id=a.user_id LEFT JOIN jobs j ON j.id=a.job_id
        JOIN business_memberships m ON m.user_id=a.user_id AND m.business_id=?
        WHERE (j.business_id=? OR (a.job_id IS NULL AND m.business_id=?))
        ORDER BY a.id DESC LIMIT ?""",(u['business_id'],u['business_id'],u['business_id'],limit))]

@app.get('/api/admin/backups')
def list_backups(u=Depends(admin)):
    with conn() as _db:
        if u['business_id']!=1 or _db.execute('SELECT COUNT(*) FROM businesses').fetchone()[0]>1:raise HTTPException(403,'Shared database backups are disabled in multi-business mode')
    folder=backup_dir(DB)
    return [{'name':p.name,'bytes':p.stat().st_size,'created_at':int(p.stat().st_mtime)}
            for p in sorted(folder.glob('*.zip'),reverse=True) if p.is_file()][:20] if folder.exists() else []

@app.post('/api/admin/backups')
def create_backup(u=Depends(admin)):
    with conn() as _db:
        if u['business_id']!=1 or _db.execute('SELECT COUNT(*) FROM businesses').fetchone()[0]>1:raise HTTPException(403,'Shared database backups are disabled in multi-business mode')
    try:p=make_backup(DB,UPLOAD_ROOT,BG_ROOT)
    except Exception as e:raise HTTPException(500,'Backup failed: '+str(e))
    return {'ok':True,'name':p.name}

@app.get('/api/admin/backups/{filename}')
def download_backup(filename:str,u=Depends(admin)):
    with conn() as _db:
        if u['business_id']!=1 or _db.execute('SELECT COUNT(*) FROM businesses').fetchone()[0]>1:raise HTTPException(403,'Shared database backups are disabled in multi-business mode')
    if not re.fullmatch(r'[0-9]{8}-[0-9]{6}-[0-9]{1,6}\.zip',filename):raise HTTPException(404)
    p=backup_dir(DB)/filename
    if not p.is_file():raise HTTPException(404)
    return FileResponse(p,media_type='application/zip',filename='SignMaster360-'+filename,headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})

@app.on_event('startup')
def _sm_backup_startup():
    start_local_backup_worker(DB,UPLOAD_ROOT,BG_ROOT)

# Stage 1 SaaS foundation. Registration deliberately locked until full isolation.
from sm360_tenants import setup as setup_tenants
setup_tenants(app,conn,pw_hash)

# Stage 2A: single-business ownership migration. New business signup remains disabled.
from sm360_isolation import install_ownership_schema as _sm_install_ownership_schema
with conn() as _sm_db:
    _sm_install_ownership_schema(_sm_db)

# Stage 2: quotation and invoice module (additive migrations only).
from sm360_documents import setup as setup_documents
setup_documents(app,conn,current,admin)

# Stage 3: deposits and payment tracking (additive tables only).
from sm360_payments import setup as setup_payments
setup_payments(app,conn,current)

from sm360_company_logo import setup as setup_company_logo
setup_company_logo(app,conn,current,admin)

# Stage 4: Meta WhatsApp Cloud API webhook (verification and secure receipt only).
from sm360_meta_webhook import setup as setup_meta_webhook
setup_meta_webhook(app)





# Stage 2B Part 2: business-scoped WhatsApp connection metadata (no secrets).
from sm360_whatsapp_tenants import setup as setup_whatsapp_tenants
setup_whatsapp_tenants(app,conn,current,admin)

# Stage 3A: subscription status preview. No new registrations or payment enforcement.
from sm360_trial import setup as setup_trial
setup_trial(app,conn,current)

# Stage 3B: internal registration/email-verification schema and primitives only.
# Public signup stays disabled until cross-tenant security review passes.
from sm360_registration import setup as setup_registration
setup_registration(app,conn)

# Stage 3C: email transport and password-reset storage, internal-only.
# Public signup/reset endpoints stay disabled pending the tenant-security audit.
from sm360_password_reset import setup as setup_password_reset
setup_password_reset(conn)

# Stage 3C follow-up: opt-in, admin-only Resend connectivity test.
from sm360_email_test import setup as setup_email_test
setup_email_test(app, conn, admin)

# Public website contact form (Resend; isolated from tenant data).
from sm360_public_support import setup as setup_public_support
setup_public_support(app)

# Stage 3D: safe public registration status + closed verification contract.
# Both account creation and verification remain disabled pending security audit.
from sm360_registration_routes import setup as setup_registration_routes
setup_registration_routes(app)

# Step 3L-B: additive sandbox payment event ledger. ITN route remains closed.
from sm360_payfast_itn import setup as setup_payfast_itn
setup_payfast_itn(app, conn)

# Step 3L-D: opt-in sandbox checkout; remains disabled by default.
from sm360_payfast_checkout import setup as setup_payfast_checkout
setup_payfast_checkout(app, conn, admin)

# Stage 6: dormant live PayFast ITN endpoint (always fails closed).
from sm360_payfast_live_route import setup as setup_payfast_live_route
setup_payfast_live_route(app)

# Tenant-scoped stock inventory (additive tables)
from sm360_stock import setup as setup_stock
setup_stock(app,conn,current)
from sm360_job_materials import setup as setup_job_materials
setup_job_materials(app,conn,current)

from sm360_job_checkout import setup as setup_job_checkout
setup_job_checkout(app,conn,current,STAGES)

# Expand the membership role constraint without removing existing accounts.
from sm360_tenants import upgrade_stock_controller_role
with conn() as _db: upgrade_stock_controller_role(_db)
from sm360_tenants import upgrade_viewer_role
with conn() as _db: upgrade_viewer_role(_db)


# Per-business Facebook Page shortcut. Stores only a public Page URL, never credentials.
with conn() as db:
    db.execute('''CREATE TABLE IF NOT EXISTS sm360_facebook_pages (
        business_id INTEGER PRIMARY KEY,
        page_url TEXT NOT NULL,
        updated_by INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )''')

class FacebookPageSetting(BaseModel):
    page_url:str=Field(min_length=15,max_length=500)

def verified_facebook_page_url(raw):
    from urllib.parse import urlsplit,urlunsplit
    value=raw.strip()
    try: parts=urlsplit(value)
    except ValueError:raise HTTPException(400,'Invalid Facebook Page URL')
    if parts.scheme!='https' or (parts.hostname or '').lower() not in ('facebook.com','www.facebook.com','m.facebook.com','web.facebook.com'):
        raise HTTPException(400,'Enter a full https://www.facebook.com/ Page URL')
    if parts.username or parts.password or parts.port or not parts.path.strip('/'):
        raise HTTPException(400,'Enter a Facebook Page URL, not the Facebook homepage')
    if any(ord(c)<32 for c in value):raise HTTPException(400,'Invalid URL')
    return urlunsplit(('https',parts.hostname.lower(),parts.path,parts.query,''))

@app.get('/api/business/facebook-page')
def get_facebook_page(u=Depends(current)):
    with conn() as db:
        row=db.execute('SELECT page_url FROM sm360_facebook_pages WHERE business_id=?',(u['business_id'],)).fetchone()
    return {'page_url':row['page_url'] if row else ''}

@app.put('/api/business/facebook-page')
def set_facebook_page(data:FacebookPageSetting,u=Depends(admin)):
    url=verified_facebook_page_url(data.page_url)
    with conn() as db:
        db.execute('''INSERT INTO sm360_facebook_pages(business_id,page_url,updated_by,updated_at)
            VALUES(?,?,?,?) ON CONFLICT(business_id) DO UPDATE SET
            page_url=excluded.page_url,updated_by=excluded.updated_by,updated_at=excluded.updated_at''',
            (u['business_id'],url,u['id'],int(time.time())))
    return {'page_url':url}


# Each account can edit only its own name and surname; existing user accounts remain intact.
with conn() as db:
    db.execute("""CREATE TABLE IF NOT EXISTS sm360_user_profiles (
        user_id INTEGER PRIMARY KEY, first_name TEXT NOT NULL, surname TEXT NOT NULL,
        updated_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id))""")

class MyProfileUpdate(BaseModel):
    first_name:str=Field(min_length=1,max_length=80)
    surname:str=Field(min_length=1,max_length=80)

def profile_fields(u):
    with conn() as db:
        p=db.execute('SELECT first_name,surname FROM sm360_user_profiles WHERE user_id=?',(u['id'],)).fetchone()
    if p:return dict(p)
    name=u['name'].strip().split(None,1)
    return {'first_name':name[0] if name else '', 'surname':name[1] if len(name)>1 else ''}

@app.get('/api/profile')
def get_my_profile(u=Depends(current)):
    return {**profile_fields(u),'email':u['email'],'role':u['role']}

@app.put('/api/profile')
def update_my_profile(data:MyProfileUpdate,u=Depends(current)):
    first=data.first_name.strip();surname=data.surname.strip()
    if not first or not surname or any(ord(c)<32 for c in first+surname):
        raise HTTPException(400,'Enter your first name and surname')
    with conn() as db:
        db.execute("""INSERT INTO sm360_user_profiles(user_id,first_name,surname,updated_at)
            VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET
            first_name=excluded.first_name,surname=excluded.surname,updated_at=excluded.updated_at""",
            (u['id'],first,surname,int(time.time())))
        db.execute('UPDATE users SET name=? WHERE id=?',(first+' '+surname,u['id']))
    return {'first_name':first,'surname':surname,'name':first+' '+surname,'email':u['email'],'role':u['role']}


# Personal avatar images: stored per user in persistent SQLite, never shared by role.
with conn() as db:
    db.execute("""CREATE TABLE IF NOT EXISTS sm360_profile_avatars (
        user_id INTEGER PRIMARY KEY, image BLOB NOT NULL, updated_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id))""")

@app.get('/api/profile/avatar')
def get_my_avatar(u=Depends(current)):
    with conn() as db:
        row=db.execute('SELECT image FROM sm360_profile_avatars WHERE user_id=?',(u['id'],)).fetchone()
    if not row:raise HTTPException(404,'No profile picture')
    return Response(content=row['image'],media_type='image/png',headers={'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'})

@app.post('/api/profile/avatar')
async def upload_my_avatar(file:UploadFile=File(...),u=Depends(current)):
    import io
    from PIL import Image,UnidentifiedImageError
    if file.content_type not in ('image/png','image/jpeg','image/webp'):
        raise HTTPException(400,'Choose a JPG, PNG or WebP image')
    content=await file.read(2*1024*1024+1)
    if len(content)>2*1024*1024:raise HTTPException(413,'Profile photo must be smaller than 2 MB')
    try:
        with Image.open(io.BytesIO(content)) as source:
            if source.format not in ('JPEG','PNG','WEBP'):raise ValueError('Invalid format')
            if source.width*source.height>16000000:raise ValueError('Image dimensions too large')
            source.load()
            img=source.convert('RGB')
        side=min(img.size);left=(img.width-side)//2;top=(img.height-side)//2
        img=img.crop((left,top,left+side,top+side));img.thumbnail((256,256))
        output=io.BytesIO();img.save(output,format='PNG',optimize=True)
    except (UnidentifiedImageError,ValueError,OSError) as e:
        raise HTTPException(400,'Invalid or unsupported profile picture') from e
    with conn() as db:
        db.execute("""INSERT INTO sm360_profile_avatars(user_id,image,updated_at) VALUES(?,?,?)
            ON CONFLICT(user_id) DO UPDATE SET image=excluded.image,updated_at=excluded.updated_at""",
            (u['id'],output.getvalue(),int(time.time())))
    return {'ok':True}

@app.delete('/api/profile/avatar')
def delete_my_avatar(u=Depends(current)):
    with conn() as db:db.execute('DELETE FROM sm360_profile_avatars WHERE user_id=?',(u['id'],))
    return {'ok':True}

# Vehicle catalogue: additive tenant-scoped measurements and reference-only master list.
from sm360_vehicle_catalogue import register as register_vehicle_catalogue
register_vehicle_catalogue(app,conn,current)

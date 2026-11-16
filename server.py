from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import sqlite3, json, secrets, hashlib, hmac, os, re, mimetypes, urllib.parse

ROOT=Path(__file__).resolve().parent
DB=Path(os.environ.get('OFIM_DB_PATH',ROOT/'ofim.sqlite3'))

def db():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
 c.executescript('''CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT,email TEXT UNIQUE,pw BLOB,salt BLOB);
 CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT,expires INTEGER);
 CREATE TABLE IF NOT EXISTS sheets(id TEXT PRIMARY KEY,owner TEXT,body TEXT);
 CREATE TABLE IF NOT EXISTS campaigns(id TEXT PRIMARY KEY,owner TEXT,name TEXT,description TEXT,token TEXT UNIQUE);
 CREATE TABLE IF NOT EXISTS members(campaign TEXT,user_id TEXT,role TEXT,PRIMARY KEY(campaign,user_id));
 CREATE TABLE IF NOT EXISTS bans(campaign TEXT,user_id TEXT,PRIMARY KEY(campaign,user_id));
 CREATE TABLE IF NOT EXISTS campaign_sheets(campaign TEXT,sheet TEXT,PRIMARY KEY(campaign,sheet));
 CREATE TABLE IF NOT EXISTS homebrew(id TEXT PRIMARY KEY,owner TEXT,campaign TEXT,body TEXT);''')
 if 'cover' not in [x['name'] for x in c.execute('PRAGMA table_info(campaigns)')]:
  c.execute("ALTER TABLE campaigns ADD COLUMN cover TEXT NOT NULL DEFAULT ''")
 return c

def row(r): return dict(r) if r else None
class App(SimpleHTTPRequestHandler):
 def __init__(self,*a,**kw): super().__init__(*a,directory=str(ROOT),**kw)
 def sendj(self,status,obj,headers=None):
  b=json.dumps(obj,ensure_ascii=False).encode(); self.send_response(status); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(b))); self.send_header('Cache-Control','no-store')
  for k,v in (headers or {}).items(): self.send_header(k,v)
  self.end_headers(); self.wfile.write(b)
 def body(self):
  n=min(int(self.headers.get('Content-Length','0')),2_000_000); return json.loads(self.rfile.read(n) or b'{}')
 def auth(self,c):
  token=(self.headers.get('Cookie','').split('ofim_session=',1)[-1].split(';',1)[0] if 'ofim_session=' in self.headers.get('Cookie','') else '')
  r=c.execute('SELECT users.* FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token=? AND sessions.expires>?',(token,__import__('time').time())).fetchone(); return row(r),token
 def do_GET(self):
  request_path=urllib.parse.urlsplit(self.path).path
  if request_path.startswith('/art/'):
   art_root=(ROOT/'art').resolve()
   target=(ROOT/urllib.parse.unquote(request_path.lstrip('/'))).resolve()
   try: target.relative_to(art_root)
   except ValueError: return self.sendj(404,{'error':'Não encontrado.'})
   if not target.is_file(): return self.sendj(404,{'error':'Não encontrado.'})
   self.path='/'+target.relative_to(ROOT).as_posix(); return super().do_GET()
  if not self.path.startswith('/api/'):
   if request_path not in ('/','/index.html'): return self.sendj(404,{'error':'Não encontrado.'})
   self.path='/index.html'; return super().do_GET()
  c=db(); user,token=self.auth(c); p=self.path.split('?')[0].split('/')
  if p[2]=='me': return self.sendj(200,{'user':{'id':user['id'],'name':user['name'],'email':user['email']} if user else None})
  if not user:return self.sendj(401,{'error':'Entre na sua conta.'})
  if p[2]=='sheets':
   out=[]
   for x in c.execute('SELECT body FROM sheets WHERE owner=? ORDER BY rowid DESC',(user['id'],)):
    item=json.loads(x['body']); item['ownerId']=user['id']; out.append(item)
   return self.sendj(200,{'sheets':out})
  if p[2]=='campaigns':
   cs=[]
   for x in c.execute('SELECT campaigns.*,members.role FROM members JOIN campaigns ON campaigns.id=members.campaign WHERE members.user_id=?',(user['id'],)):
    cs.append({'id':x['id'],'name':x['name'],'description':x['description'],'role':x['role'],'invite':x['token'] if x['owner']==user['id'] else None})
   return self.sendj(200,{'campaigns':cs})
  if p[2]=='homebrew':
   return self.sendj(200,{'homebrew':[json.loads(x['body']) for x in c.execute('SELECT body FROM homebrew WHERE owner=? OR campaign IN (SELECT campaign FROM members WHERE user_id=?)',(user['id'],user['id']))]})
  if p[2]=='campaign' and len(p)>3:
   cid=p[3]; mem=c.execute('SELECT role FROM members WHERE campaign=? AND user_id=?',(cid,user['id'])).fetchone()
   if not mem:return self.sendj(403,{'error':'Sem acesso à campanha.'})
   camp=c.execute('SELECT * FROM campaigns WHERE id=?',(cid,)).fetchone(); members=[dict(x) for x in c.execute('SELECT users.id,users.name,members.role FROM members JOIN users ON users.id=members.user_id WHERE campaign=?',(cid,))]
   sheets=[]
   for x in c.execute('SELECT sheets.body,sheets.owner FROM campaign_sheets JOIN sheets ON sheets.id=campaign_sheets.sheet WHERE campaign=?',(cid,)):
    item=json.loads(x['body']); item['ownerId']=x['owner']; sheets.append(item)
   return self.sendj(200,{'campaign':{'id':cid,'name':camp['name'],'description':camp['description'],'cover':camp['cover'] or '','role':mem['role'],'invite':camp['token'] if camp['owner']==user['id'] else None},'members':members,'sheets':sheets})
  return self.sendj(404,{'error':'Não encontrado.'})
 def do_POST(self):
  if not self.path.startswith('/api/'):return self.sendj(404,{})
  c=db(); p=self.path.split('?')[0].split('/'); d=self.body()
  if p[2]=='register':
   name=str(d.get('name','')).strip(); email=str(d.get('email','')).strip().lower(); pw=str(d.get('password',''))
   if not name or '@' not in email or len(pw)<8:return self.sendj(400,{'error':'Informe nome, e-mail e senha com pelo menos 8 caracteres.'})
   salt=secrets.token_bytes(16); hashed=hashlib.scrypt(pw.encode(),salt=salt,n=2**14,r=8,p=1)
   try:c.execute('INSERT INTO users VALUES(?,?,?,?,?)',(secrets.token_urlsafe(12),name,email,hashed,salt)); c.commit()
   except sqlite3.IntegrityError:return self.sendj(409,{'error':'Este e-mail já possui conta.'})
   return self.login(c,email,pw)
  if p[2]=='login':return self.login(c,str(d.get('email','')).lower(),str(d.get('password','')))
  if p[2]=='logout':
   u,t=self.auth(c); c.execute('DELETE FROM sessions WHERE token=?',(t,)); c.commit(); return self.sendj(200,{'ok':True}, {'Set-Cookie':'ofim_session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/'})
  user,_=self.auth(c)
  if not user:return self.sendj(401,{'error':'Entre na sua conta.'})
  if p[2]=='sheets':
   data=d.get('sheet',{}); sid=data.get('id') or secrets.token_urlsafe(12); data['id']=sid; c.execute('INSERT INTO sheets VALUES(?,?,?)',(sid,user['id'],json.dumps(data,ensure_ascii=False))); c.commit(); return self.sendj(200,{'sheet':data})
  if p[2]=='sheet' and len(p)>3:
   sid=p[3]; owner=c.execute('SELECT owner FROM sheets WHERE id=?',(sid,)).fetchone(); allowed=owner and owner['owner']==user['id']
   gm=c.execute('SELECT 1 FROM campaign_sheets cs JOIN members m ON m.campaign=cs.campaign WHERE cs.sheet=? AND m.user_id=? AND m.role="gm"',(sid,user['id'])).fetchone(); allowed=allowed or gm
   if not allowed:return self.sendj(403,{'error':'Sem permissão para editar.'})
   data=d.get('sheet',{}); data['id']=sid;c.execute('UPDATE sheets SET body=? WHERE id=?',(json.dumps(data,ensure_ascii=False),sid));c.commit();return self.sendj(200,{'sheet':data})
  if p[2]=='campaigns':
   cid=secrets.token_urlsafe(12); tok=secrets.token_urlsafe(24); name=str(d.get('name','')).strip()
   if not name:return self.sendj(400,{'error':'Informe o nome da campanha.'})
   c.execute('INSERT INTO campaigns(id,owner,name,description,token,cover) VALUES(?,?,?,?,?,?)',(cid,user['id'],name,str(d.get('description','')),tok,str(d.get('cover',''))));c.execute('INSERT INTO members VALUES(?,?,?)',(cid,user['id'],'gm'));c.commit();return self.sendj(200,{'id':cid,'invite':tok})
  if p[2]=='join':
   tok=str(d.get('token','')); camp=c.execute('SELECT * FROM campaigns WHERE token=?',(tok,)).fetchone()
   if not camp:return self.sendj(404,{'error':'Link de convite inválido.'})
   if c.execute('SELECT 1 FROM bans WHERE campaign=? AND user_id=?',(camp['id'],user['id'])).fetchone():return self.sendj(403,{'error':'Seu acesso à campanha foi removido.'})
   c.execute('INSERT OR IGNORE INTO members VALUES(?,?,?)',(camp['id'],user['id'],'player'));c.commit();return self.sendj(200,{'id':camp['id']})
  if p[2]=='campaign' and len(p)>4:
   cid,action=p[3],p[4]; mem=c.execute('SELECT role FROM members WHERE campaign=? AND user_id=?',(cid,user['id'])).fetchone()
   if not mem:return self.sendj(403,{'error':'Sem acesso.'})
   if action=='add-sheet':
    sid=d.get('sheet'); own=c.execute('SELECT 1 FROM sheets WHERE id=? AND owner=?',(sid,user['id'])).fetchone()
    if not own:return self.sendj(403,{'error':'Você só pode adicionar uma ficha sua.'})
    c.execute('INSERT OR IGNORE INTO campaign_sheets VALUES(?,?)',(cid,sid));c.commit();return self.sendj(200,{'ok':True})
   if action=='remove-sheet':
    sid=d.get('sheet'); owner=c.execute('SELECT owner FROM sheets WHERE id=?',(sid,)).fetchone()
    if not owner or (mem['role']!='gm' and owner['owner']!=user['id']):return self.sendj(403,{'error':'Sem permissão para remover esta ficha.'})
    c.execute('DELETE FROM campaign_sheets WHERE campaign=? AND sheet=?',(cid,sid));c.commit();return self.sendj(200,{'ok':True})
   if action=='update' and mem['role']=='gm':
    c.execute('UPDATE campaigns SET name=?,description=?,cover=? WHERE id=?',(str(d.get('name','')).strip(),str(d.get('description','')),str(d.get('cover','')),cid));c.commit();return self.sendj(200,{'ok':True})
   if action=='revoke-link' and mem['role']=='gm':
    tok=secrets.token_urlsafe(24);c.execute('UPDATE campaigns SET token=? WHERE id=?',(tok,cid));c.commit();return self.sendj(200,{'invite':tok})
   if action=='kick' and mem['role']=='gm':
    uid=d.get('user');c.execute('DELETE FROM members WHERE campaign=? AND user_id=?',(cid,uid));c.execute('INSERT OR IGNORE INTO bans VALUES(?,?)',(cid,uid));c.commit();return self.sendj(200,{'ok':True})
   if action=='invite' and mem['role']=='gm':return self.sendj(200,{'invite':c.execute('SELECT token FROM campaigns WHERE id=?',(cid,)).fetchone()['token']})
  if p[2]=='homebrew':
   item=d.get('item',{}); item['id']=item.get('id') or secrets.token_urlsafe(12); cid=item.get('campaign');
   if cid and not c.execute('SELECT 1 FROM members WHERE campaign=? AND user_id=?',(cid,user['id'])).fetchone():return self.sendj(403,{'error':'Sem acesso à campanha escolhida.'})
   c.execute('INSERT INTO homebrew VALUES(?,?,?,?)',(item['id'],user['id'],cid,json.dumps(item,ensure_ascii=False))); c.commit();return self.sendj(200,{'item':item})
  return self.sendj(404,{'error':'Não encontrado.'})
 def login(self,c,email,pw):
  u=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
  if not u or not hmac.compare_digest(hashlib.scrypt(pw.encode(),salt=u['salt'],n=2**14,r=8,p=1),u['pw']):return self.sendj(401,{'error':'E-mail ou senha incorretos.'})
  token=secrets.token_urlsafe(32);c.execute('INSERT INTO sessions VALUES(?,?,?)',(token,u['id'],__import__('time').time()+30*86400));c.commit();return self.sendj(200,{'user':{'id':u['id'],'name':u['name'],'email':u['email']}},{'Set-Cookie':'ofim_session='+token+'; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000'})
 def do_DELETE(self):
  c=db();p=self.path.split('?')[0].split('/');user,_=self.auth(c)
  if not user:return self.sendj(401,{'error':'Entre na sua conta.'})
  if len(p)==4 and p[2]=='sheet':
   sid=p[3];own=c.execute('SELECT owner FROM sheets WHERE id=?',(sid,)).fetchone();gm=c.execute('SELECT 1 FROM campaign_sheets cs JOIN members m ON m.campaign=cs.campaign WHERE cs.sheet=? AND m.user_id=? AND m.role="gm"',(sid,user['id'])).fetchone()
   if not own or (own['owner']!=user['id'] and not gm):return self.sendj(403,{'error':'Sem permissão.'})
   c.execute('DELETE FROM campaign_sheets WHERE sheet=?',(sid,));c.execute('DELETE FROM sheets WHERE id=?',(sid,));c.commit();return self.sendj(200,{'ok':True})
  if len(p)==4 and p[2]=='campaign':
   cid=p[3]; gm=c.execute('SELECT 1 FROM members WHERE campaign=? AND user_id=? AND role="gm"',(cid,user['id'])).fetchone()
   if not gm:return self.sendj(403,{'error':'Sem permissão.'})
   c.execute('DELETE FROM campaign_sheets WHERE campaign=?',(cid,));c.execute('DELETE FROM members WHERE campaign=?',(cid,));c.execute('DELETE FROM bans WHERE campaign=?',(cid,));c.execute('DELETE FROM campaigns WHERE id=?',(cid,));c.commit();return self.sendj(200,{'ok':True})
  if len(p)==4 and p[2]=='homebrew':
   hid=p[3]; c.execute('DELETE FROM homebrew WHERE id=? AND owner=?',(hid,user['id']));c.commit();return self.sendj(200,{'ok':True})
  return self.sendj(404,{})

if __name__=='__main__':
 db().close(); port=int(os.environ.get('PORT','8000')); host=os.environ.get('HOST','127.0.0.1'); print('O FIM disponível em http://'+host+':'+str(port)); ThreadingHTTPServer((host,port),App).serve_forever()

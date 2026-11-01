from flask import Flask, request, jsonify, session, render_template
import sqlite3, os, secrets, hashlib, time
from functools import wraps

BASE=os.path.dirname(os.path.abspath(__file__))
DB=os.path.join(BASE,'students.db')
app=Flask(__name__)
app.secret_key=os.environ.get('SECRET_KEY',secrets.token_hex(32))
TOPICS=[
('networking','Networking Fundamentals'),('linux','Linux Fundamentals'),('python','Python for Cyber Security'),
('security','Cyber Security Fundamentals'),('passwords','Password Security'),('dns','DNS & Ports'),
('web','Web Security Basics'),('crypto','Cryptography Basics'),('soc','SOC & Blue Team'),
('forensics','Digital Forensics'),('cloud','Cloud Security'),('iam','Identity & Access Management'),('risk','Risk & Security Fundamentals')]

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init_db():
    c=db(); c.executescript('''
    CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS progress(student_id INTEGER,topic TEXT,completed INTEGER DEFAULT 0,PRIMARY KEY(student_id,topic));
    CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER,title TEXT,body TEXT,updated_at INTEGER);
    CREATE TABLE IF NOT EXISTS quiz_attempts(id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER,score INTEGER,total INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS achievements(student_id INTEGER,key TEXT,title TEXT,PRIMARY KEY(student_id,key));
    '''); c.commit(); c.close()

def hash_pw(p):
    salt=secrets.token_bytes(16); h=hashlib.pbkdf2_hmac('sha256',p.encode(),salt,220000); return salt.hex()+':'+h.hex()
def check_pw(p,s):
    try:
        a,b=s.split(':',1); h=hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(a),220000).hex(); return secrets.compare_digest(h,b)
    except: return False

def auth(f):
    @wraps(f)
    def w(*a,**k):
        if 'student_id' not in session:return jsonify(ok=False,error='Please login first.'),401
        return f(*a,**k)
    return w
@app.get('/')
def home(): return render_template('index.html')
@app.post('/api/register')
def register():
    d=request.get_json(silent=True) or {}; u=str(d.get('username','')).strip(); p=str(d.get('password',''))
    if not 3<=len(u)<=30:return jsonify(ok=False,error='Username must be 3-30 characters.'),400
    if len(p)<8:return jsonify(ok=False,error='Password must be at least 8 characters.'),400
    c=db()
    try:
        sid=c.execute('INSERT INTO students(username,password_hash) VALUES(?,?)',(u,hash_pw(p))).lastrowid
        for k,_ in TOPICS:c.execute('INSERT INTO progress VALUES(?,?,0)',(sid,k))
        c.commit()
    except sqlite3.IntegrityError:c.close();return jsonify(ok=False,error='Username already exists.'),409
    c.close();session['student_id']=sid;session['username']=u;return jsonify(ok=True,username=u)
@app.post('/api/login')
def login():
    d=request.get_json(silent=True) or {};u=str(d.get('username','')).strip();p=str(d.get('password',''))
    c=db();r=c.execute('SELECT * FROM students WHERE username=?',(u,)).fetchone();c.close()
    if not r or not check_pw(p,r['password_hash']):return jsonify(ok=False,error='Wrong username or password.'),401
    session['student_id']=r['id'];session['username']=r['username'];return jsonify(ok=True,username=u)
@app.post('/api/logout')
def logout():session.clear();return jsonify(ok=True)
@app.get('/api/me')
def me():
    if 'student_id' not in session:return jsonify(logged_in=False)
    sid=session['student_id'];c=db();rows=c.execute('SELECT topic,completed FROM progress WHERE student_id=?',(sid,)).fetchall()
    attempts=c.execute('SELECT score,total,created_at FROM quiz_attempts WHERE student_id=? ORDER BY id DESC LIMIT 20',(sid,)).fetchall()
    ach=c.execute('SELECT key,title FROM achievements WHERE student_id=?',(sid,)).fetchall(); notes=c.execute('SELECT COUNT(*) n FROM notes WHERE student_id=?',(sid,)).fetchone()['n'];c.close()
    done=sum(x['completed'] for x in rows); total=len(TOPICS)
    return jsonify(logged_in=True,username=session['username'],completed=done,total=total,percent=round(done*100/total),notes=notes,points=sum(x['score']*10 for x in attempts),topics=[dict(x) for x in rows],attempts=[dict(x) for x in attempts],achievements=[dict(x) for x in ach])
@app.post('/api/progress')
@auth
def progress():
    d=request.get_json(silent=True) or {};k=d.get('topic');v=1 if d.get('completed') else 0
    if k not in dict(TOPICS):return jsonify(ok=False,error='Unknown topic.'),400
    c=db();sid=session['student_id'];c.execute('UPDATE progress SET completed=? WHERE student_id=? AND topic=?',(v,sid,k));
    n=c.execute('SELECT COUNT(*) n FROM progress WHERE student_id=? AND completed=1',(sid,)).fetchone()['n']
    if n>=1:c.execute('INSERT OR IGNORE INTO achievements VALUES(?,?,?)',(sid,'first','First Topic'))
    if n>=5:c.execute('INSERT OR IGNORE INTO achievements VALUES(?,?,?)',(sid,'five','5 Topics Complete'))
    if n>=10:c.execute('INSERT OR IGNORE INTO achievements VALUES(?,?,?)',(sid,'ten','10 Topics Complete'))
    if n==len(TOPICS):c.execute('INSERT OR IGNORE INTO achievements VALUES(?,?,?)',(sid,'master','Roadmap Master'))
    c.commit();c.close();return jsonify(ok=True)
@app.get('/api/notes')
@auth
def get_notes():
    c=db();r=c.execute('SELECT id,title,body,updated_at FROM notes WHERE student_id=? ORDER BY updated_at DESC',(session['student_id'],)).fetchall();c.close();return jsonify(notes=[dict(x) for x in r])
@app.post('/api/notes')
@auth
def save_note():
    d=request.get_json(silent=True) or {};title=str(d.get('title','Untitled'))[:100];body=str(d.get('body',''))[:12000];c=db()
    if d.get('id'):c.execute('UPDATE notes SET title=?,body=?,updated_at=? WHERE id=? AND student_id=?',(title,body,int(time.time()),d['id'],session['student_id']))
    else:c.execute('INSERT INTO notes(student_id,title,body,updated_at) VALUES(?,?,?,?)',(session['student_id'],title,body,int(time.time())))
    c.commit();c.close();return jsonify(ok=True)
@app.delete('/api/notes/<int:nid>')
@auth
def del_note(nid):
    c=db();c.execute('DELETE FROM notes WHERE id=? AND student_id=?',(nid,session['student_id']));c.commit();c.close();return jsonify(ok=True)
@app.post('/api/quiz')
@auth
def quiz():
    d=request.get_json(silent=True) or {};score=max(0,int(d.get('score',0)));total=max(1,int(d.get('total',5)));score=min(score,total);c=db();sid=session['student_id'];c.execute('INSERT INTO quiz_attempts(student_id,score,total) VALUES(?,?,?)',(sid,score,total))
    if score==total:c.execute('INSERT OR IGNORE INTO achievements VALUES(?,?,?)',(sid,'perfect','Perfect Quiz'))
    c.commit();c.close();return jsonify(ok=True)
@app.get('/api/leaderboard')
def leaderboard():
    c=db();r=c.execute('SELECT s.username,COALESCE(SUM(q.score*10),0) points FROM students s LEFT JOIN quiz_attempts q ON q.student_id=s.id GROUP BY s.id ORDER BY points DESC,s.username LIMIT 10').fetchall();c.close();return jsonify(leaderboard=[dict(x) for x in r])
if __name__=='__main__':init_db();print('Open http://127.0.0.1:8000');app.run(host='127.0.0.1',port=8000,debug=False)

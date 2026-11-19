# -*- coding: utf-8 -*-
"""Sistema de Chamados de TI - Flask + SQLite (arquivo unico).
Solicitante: digita o nome e abre o chamado (sem conta). Tecnico: login por senha.
Aviso no Telegram a cada chamado novo e a cada nota do solicitante."""
import os, sys, sqlite3, secrets, hmac, time, uuid, threading, urllib.request, urllib.parse, json
from datetime import datetime
from zoneinfo import ZoneInfo
from functools import wraps
from flask import (Flask, g, request, session, redirect, url_for, abort,
                   render_template, send_from_directory, jsonify, flash)
from jinja2 import DictLoader

# ---------------- CONFIGURACAO (pode usar variaveis de ambiente) ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("CHAMADOS_DATA", os.path.join(BASE_DIR, "dados"))
TECH_PASSWORD = os.environ.get("CHAMADOS_SENHA", "123456")          # OBRIGATORIA
TECH_NAME = os.environ.get("CHAMADOS_TECNICO", "Suporte TI")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")          # token do BotFather
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")      # seu chat id
BASE_URL = os.environ.get("CHAMADOS_URL", "").rstrip("/")      # ex.: http://srv-ti:8080
PORT = int(os.environ.get("PORT", os.environ.get("CHAMADOS_PORTA", "8080")))
BEHIND_PROXY = os.environ.get("CHAMADOS_PROXY", "") == "1"   # use 1 se estiver atras do IIS/proxy
PORTAL_DIR = os.path.join(BASE_DIR, "portal")
MAX_FILES, MAX_FILE_MB = 5, 5
STATUS = ["Aberto", "Em andamento", "Resolvido"]
PRIOS = ["Baixa", "Média", "Alta"]
CATS = ["Hardware", "Software", "Rede", "Acesso/Senha", "Impressora", "Outro"]
# --------------------------------------------------------------------------------

os.makedirs(os.path.join(DATA_DIR, "uploads"), exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "chamados.db")

def _secret():
    p = os.path.join(DATA_DIR, "secret.key")
    if not os.path.exists(p):
        with open(p, "w") as f: f.write(secrets.token_hex(32))
    return open(p).read().strip()

app = Flask(__name__)
app.secret_key = _secret()
if BEHIND_PROXY:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(MAX_CONTENT_LENGTH=(MAX_FILES * MAX_FILE_MB + 2) * 1024 * 1024,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 90)

# ---------------- banco ----------------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def _close(_):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    c = sqlite3.connect(DB_PATH)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS tickets(id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT UNIQUE,
      name TEXT, sector TEXT, title TEXT, category TEXT, priority TEXT, description TEXT,
      status TEXT DEFAULT 'Aberto', tech TEXT, created REAL, updated REAL);
    CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_id INTEGER REFERENCES tickets(id) ON DELETE CASCADE, author TEXT, is_tech INTEGER, text TEXT, created REAL);
    CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_id INTEGER REFERENCES tickets(id) ON DELETE CASCADE, filename TEXT, orig TEXT);
    """)
    c.commit(); c.close()

# ---------------- utilidades ----------------
def notify(text):
    if not (TELEGRAM_TOKEN and TELEGRAM_CHAT_ID): return
    def run():
        try:
            data = urllib.parse.urlencode({"chat_id": TELEGRAM_CHAT_ID, "text": text}).encode()
            urllib.request.urlopen(urllib.request.Request(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", data=data), timeout=10).read()
        except Exception as e:
            print("Falha no Telegram:", e, file=sys.stderr)
    threading.Thread(target=run, daemon=True).start()

def sniff(b):
    if b[:8] == b"\x89PNG\r\n\x1a\n": return "png"
    if b[:3] == b"\xff\xd8\xff": return "jpg"
    if b[:6] in (b"GIF87a", b"GIF89a"): return "gif"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP": return "webp"
    return None

def save_files(ticket_id):
    n = 0
    for f in request.files.getlist("prints")[:MAX_FILES]:
        data = f.read(MAX_FILE_MB * 1024 * 1024 + 1)
        if not data or len(data) > MAX_FILE_MB * 1024 * 1024: continue
        ext = sniff(data)
        if not ext: continue
        name = uuid.uuid4().hex + "." + ext
        with open(os.path.join(DATA_DIR, "uploads", name), "wb") as o: o.write(data)
        db().execute("INSERT INTO files(ticket_id,filename,orig) VALUES(?,?,?)",
                     (ticket_id, name, (f.filename or "print")[:80]))
        n += 1
    return n

def tech_required(fn):
    @wraps(fn)
    def w(*a, **k):
        if not session.get("tech"): return redirect(url_for("login"))
        return fn(*a, **k)
    return w

def get_ticket(**kw):
    col, val = list(kw.items())[0]
    t = db().execute(f"SELECT * FROM tickets WHERE {col}=?", (val,)).fetchone()
    if not t: abort(404)
    return t

def ticket_extra(t):
    notes = db().execute("SELECT * FROM notes WHERE ticket_id=? ORDER BY created", (t["id"],)).fetchall()
    files = db().execute("SELECT * FROM files WHERE ticket_id=?", (t["id"],)).fetchall()
    return notes, files

def add_note(tid, author, is_tech, text):
    db().execute("INSERT INTO notes(ticket_id,author,is_tech,text,created) VALUES(?,?,?,?,?)",
                 (tid, author, is_tech, text, time.time()))
    db().execute("UPDATE tickets SET updated=? WHERE id=?", (time.time(), tid))

@app.before_request
def _csrf():
    if "csrf" not in session: session["csrf"] = secrets.token_hex(16)
    if request.method == "POST":
        if not hmac.compare_digest(request.form.get("csrf", ""), session["csrf"]): abort(400)

@app.template_filter("dt")
def _dt(ts):
    if ts is None: return "—"
    return datetime.fromtimestamp(ts, ZoneInfo("America/Sao_Paulo")).strftime("%d/%m/%Y %H:%M")

@app.context_processor
def _ctx(): return dict(csrf=session.get("csrf", ""), STATUS=STATUS, PRIOS=PRIOS, CATS=CATS, is_tech=session.get("tech"))

# ---------------- portal ----------------
@app.route("/")
def portal():
    return send_from_directory(PORTAL_DIR, "index.html")

@app.route("/logo.png")
def logo():
    return send_from_directory(PORTAL_DIR, "logo.png")

# ---------------- solicitante ----------------
@app.route("/chamados")
def index():
    mine = session.get("mine", [])
    rows = []
    if mine:
        q = ",".join("?" * len(mine))
        rows = db().execute(f"SELECT * FROM tickets WHERE token IN ({q}) ORDER BY created DESC", mine).fetchall()
    return render_template("index.html", rows=rows, name=session.get("name", ""), max_files=MAX_FILES)

@app.post("/abrir")
def abrir():
    f = request.form
    name, title = f.get("name", "").strip()[:60], f.get("title", "").strip()[:120]
    if not name or not title:
        flash("Informe seu nome e o título do chamado."); return redirect(url_for("index"))
    prio = f.get("priority") if f.get("priority") in PRIOS else "Média"
    cat = f.get("category") if f.get("category") in CATS else "Outro"
    token = secrets.token_urlsafe(12); now = time.time()
    cur = db().execute("""INSERT INTO tickets(token,name,sector,title,category,priority,description,created,updated)
        VALUES(?,?,?,?,?,?,?,?,?)""", (token, name, f.get("sector", "").strip()[:60] or "—", title, cat, prio,
                                       f.get("description", "").strip()[:4000], now, now))
    tid = cur.lastrowid; nf = save_files(tid); db().commit()
    session.permanent = True; session["name"] = name
    session["mine"] = ([token] + session.get("mine", []))[:30]
    link = f"\n{BASE_URL}/tecnico/{tid}" if BASE_URL else ""
    notify(f"🆕 Chamado #{tid} ({prio})\n{title}\nDe: {name} · {f.get('sector','').strip() or '—'}\nCategoria: {cat} · Prints: {nf}{link}")
    return redirect(url_for("acompanhar", token=token))

@app.route("/c/<token>")
def acompanhar(token):
    t = get_ticket(token=token); notes, files = ticket_extra(t)
    return render_template("ticket.html", t=t, notes=notes, files=files, tech=False)

@app.post("/c/<token>/nota")
def nota_solic(token):
    t = get_ticket(token=token); txt = request.form.get("text", "").strip()[:2000]
    if txt:
        add_note(t["id"], t["name"], 0, txt); db().commit()
        notify(f"💬 Nota no chamado #{t['id']} ({t['title']})\n{t['name']}: {txt[:300]}")
    return redirect(url_for("acompanhar", token=token))

@app.post("/c/<token>/resolver")
def resolver(token):
    t = get_ticket(token=token)
    db().execute("UPDATE tickets SET status='Resolvido' WHERE id=?", (t["id"],))
    add_note(t["id"], t["name"], 0, "Solicitante marcou como resolvido."); db().commit()
    notify(f"✅ Chamado #{t['id']} marcado como resolvido por {t['name']}.")
    return redirect(url_for("acompanhar", token=token))

@app.route("/c/<token>/atualizacoes")
def atualizacoes_solicitante(token):
    """Retorna novas mensagens e o status sem recarregar a página."""
    t = get_ticket(token=token)
    return _ticket_updates_json(t)


def _ticket_updates_json(t):
    try:
        after_id = max(0, int(request.args.get("after", "0")))
    except (TypeError, ValueError):
        after_id = 0
    rows = db().execute(
        "SELECT id, author, is_tech, text, created FROM notes "
        "WHERE ticket_id=? AND id>? ORDER BY id", (t["id"], after_id)
    ).fetchall()
    return jsonify(
        status=t["status"], updated=t["updated"],
        notes=[{"id": n["id"], "author": n["author"], "is_tech": bool(n["is_tech"]),
                "text": n["text"], "created": _dt(n["created"])} for n in rows]
    ), 200, {"Cache-Control": "no-store"}

@app.route("/uploads/<fn>")
def uploads(fn): return send_from_directory(os.path.join(DATA_DIR, "uploads"), fn)

# ---------------- tecnico ----------------
_fails = {}
@app.route("/tecnico/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr; n, until = _fails.get(ip, (0, 0))
        if time.time() < until:
            flash("Muitas tentativas. Aguarde alguns minutos."); return render_template("login.html")
        if hmac.compare_digest(request.form.get("password", ""), TECH_PASSWORD):
            _fails.pop(ip, None); session.clear(); session["tech"] = True; session.permanent = True
            return redirect(url_for("painel"))
        n += 1; _fails[ip] = (n, time.time() + 300 if n >= 5 else 0)
        flash("Senha incorreta.")
    return render_template("login.html")

@app.post("/tecnico/sair")
def sair():
    session.clear(); return redirect(url_for("index"))

@app.route("/tecnico")
@tech_required
def painel():
    q, st, pr = request.args.get("q", "").strip(), request.args.get("status", ""), request.args.get("prio", "")
    sql, par = "SELECT * FROM tickets WHERE 1=1", []
    if st in STATUS: sql += " AND status=?"; par.append(st)
    if pr in PRIOS: sql += " AND priority=?"; par.append(pr)
    if q: sql += " AND (title LIKE ? OR name LIKE ? OR CAST(id AS TEXT)=?)"; par += [f"%{q}%", f"%{q}%", q.lstrip("#")]
    rows = db().execute(sql + " ORDER BY (status='Resolvido'), created DESC", par).fetchall()
    cnt = {r["status"]: r["n"] for r in db().execute("SELECT status, COUNT(*) n FROM tickets GROUP BY status")}
    state = db().execute("SELECT COALESCE(MAX(id),0) m, COALESCE(MAX(updated),0) updated FROM tickets").fetchone()
    return render_template("painel.html", rows=rows, cnt=cnt, total=sum(cnt.values()), q=q, st=st, pr=pr,
                           mx=state["m"], mupdated=state["updated"])

@app.route("/tecnico/ultimo")
@tech_required
def ultimo():
    row = db().execute("SELECT COALESCE(MAX(id),0) m, COALESCE(MAX(updated),0) updated FROM tickets").fetchone()
    return jsonify(max=row["m"], updated=row["updated"]), 200, {"Cache-Control": "no-store"}

@app.route("/tecnico/<int:tid>")
@tech_required
def detalhe(tid):
    t = get_ticket(id=tid); notes, files = ticket_extra(t)
    return render_template("ticket.html", t=t, notes=notes, files=files, tech=True)

@app.route("/tecnico/<int:tid>/atualizacoes")
@tech_required
def atualizacoes_tecnico(tid):
    t = get_ticket(id=tid)
    return _ticket_updates_json(t)

@app.post("/tecnico/<int:tid>/<acao>")
@tech_required
def acao(tid, acao):
    t = get_ticket(id=tid)
    if acao == "status" and request.form.get("status") in STATUS:
        s = request.form["status"]; db().execute("UPDATE tickets SET status=?, updated=? WHERE id=?", (s, time.time(), tid))
        add_note(tid, TECH_NAME, 1, f"Status alterado para: {s}")
    elif acao == "assumir":
        db().execute("UPDATE tickets SET tech=?, status=CASE WHEN status='Aberto' THEN 'Em andamento' ELSE status END WHERE id=?", (TECH_NAME, tid))
        add_note(tid, TECH_NAME, 1, "Chamado assumido.")
    elif acao == "nota" and request.form.get("text", "").strip():
        add_note(tid, TECH_NAME, 1, request.form["text"].strip()[:2000])
    elif acao == "excluir":
        for f in db().execute("SELECT filename FROM files WHERE ticket_id=?", (tid,)):
            try: os.remove(os.path.join(DATA_DIR, "uploads", f["filename"]))
            except OSError: pass
        db().execute("DELETE FROM tickets WHERE id=?", (tid,)); db().commit()
        return redirect(url_for("painel"))
    else: abort(400)
    db().commit(); return redirect(url_for("detalhe", tid=tid))

# ---------------- templates ----------------
CSS = """
:root{--bg:#f6f7f9;--card:#fff;--tx:#1b1f24;--mut:#677084;--bd:#dfe3ea;--ac:#2563eb;--act:#fff;--ok:#15803d;--wa:#b45309;--er:#b91c1c;--in:#1d4ed8}
@media(prefers-color-scheme:dark){:root{--bg:#12151a;--card:#1b2028;--tx:#e8ebf0;--mut:#9aa4b5;--bd:#2d3542;--ac:#4f8cff;--act:#0b1220;--ok:#4ade80;--wa:#fbbf24;--er:#f87171;--in:#7aa7ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.45 system-ui,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:16px}h1{font-size:1.35rem;margin:0}h2{font-size:1.1rem}
.top{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:14px;flex-wrap:wrap}
a{color:var(--ac)}button,input,select,textarea{font:inherit;color:var(--tx)}
button,.btn{cursor:pointer;border:1px solid var(--bd);background:var(--card);padding:8px 12px;border-radius:8px;text-decoration:none;color:var(--tx);display:inline-block}
.pri{background:var(--ac);color:var(--act);border-color:var(--ac);font-weight:600}.dan{color:var(--er)}
input,select,textarea{width:100%;padding:8px 10px;border:1px solid var(--bd);border-radius:8px;background:var(--card)}
textarea{min-height:90px;resize:vertical}label{display:block;margin:10px 0 4px;font-size:.85rem;color:var(--mut)}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px;margin-bottom:10px}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:8px}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0}.row select{width:auto}
.me{color:var(--mut);font-size:.82rem}.b{font-size:.72rem;padding:2px 8px;border-radius:99px;border:1px solid currentColor;white-space:nowrap}
.s-Aberto{color:var(--in)}.s-Em.andamento,.s-Em{color:var(--wa)}.s-Resolvido{color:var(--ok)}.p-Alta{color:var(--er)}.p-Média{color:var(--wa)}.p-Baixa{color:var(--mut)}
.item{display:flex;justify-content:space-between;gap:10px;align-items:center;text-decoration:none;color:var(--tx)}.badges{display:flex;gap:6px;flex-wrap:wrap}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px}.stat{text-align:center;padding:10px;margin:0;text-decoration:none;color:var(--tx)}.stat b{display:block;font-size:1.5rem}
.bar{display:grid;grid-template-columns:2fr 1fr 1fr auto;gap:8px;margin-bottom:12px}
.note{background:var(--bg);border-radius:8px;padding:8px 10px;margin:6px 0;font-size:.9rem}.note.t{border-left:3px solid var(--ac)}.note small{color:var(--mut)}
.imgs{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}.imgs img{height:90px;max-width:160px;object-fit:cover;border-radius:8px;border:1px solid var(--bd)}
.flash{background:var(--er);color:#fff;padding:8px 12px;border-radius:8px;margin-bottom:10px}pre{white-space:pre-wrap;font:inherit;margin:8px 0}
#toast{position:fixed;top:12px;left:50%;transform:translateX(-50%);background:var(--ac);color:var(--act);padding:10px 16px;border-radius:10px;display:none;font-weight:600}
@media(max-width:560px){.stats{grid-template-columns:repeat(2,1fr)}.bar{grid-template-columns:1fr 1fr}.bar input{grid-column:1/-1}.g2{grid-template-columns:1fr}}
"""
BASE = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}Chamados de TI{% endblock %}</title><style>""" + CSS + """</style></head><body><div id="toast"></div><div class="wrap">
<div class="top"><h1><a href="{{ url_for('painel') if is_tech else url_for('portal') }}" style="text-decoration:none;color:inherit">🛠️ Chamados de TI</a></h1>
<div class="row" style="margin:0">{% if is_tech %}<form method="post" action="{{ url_for('sair') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><button>Sair</button></form>
{% else %}<a class="me" href="{{ url_for('index') }}">Abrir chamado</a> <a class="me" href="{{ url_for('login') }}">Área do técnico</a>{% endif %}</div></div>
{% for m in get_flashed_messages() %}<div class="flash">{{ m }}</div>{% endfor %}{% block body %}{% endblock %}</div></body></html>"""
INDEX = """{% extends 'base.html' %}{% block body %}
<form class="card" method="post" action="{{ url_for('abrir') }}" enctype="multipart/form-data"><h2 style="margin-top:0">Abrir chamado</h2>
<input type="hidden" name="csrf" value="{{ csrf }}">
<div class="g2"><div><label>Seu nome *</label><input name="name" value="{{ name }}" required maxlength="60"></div><div><label>Setor</label><input name="sector" maxlength="60"></div></div>
<label>Título *</label><input name="title" required maxlength="120" placeholder="Ex.: impressora não imprime">
<div class="g2"><div><label>Categoria</label><select name="category">{% for c in CATS %}<option>{{ c }}</option>{% endfor %}</select></div>
<div><label>Prioridade</label><select name="priority">{% for p in PRIOS %}<option {{ 'selected' if p=='Média' }}>{{ p }}</option>{% endfor %}</select></div></div>
<label>Descrição</label><textarea name="description"></textarea>
<label>Prints (escolha imagens ou cole com Ctrl+V, até {{ max_files }})</label><input type="file" id="f" name="prints" accept="image/*" multiple><div class="imgs" id="prev"></div>
<div class="row"><button class="pri">Abrir chamado</button></div></form>
{% if rows %}<h2>Seus chamados neste computador</h2>{% for r in rows %}<a class="card item" href="{{ url_for('acompanhar', token=r['token']) }}"><div><b>#{{ r['id'] }} {{ r['title'] }}</b><div class="me">{{ r['created']|dt }}</div></div><span class="b s-{{ r['status'].split()[0] }}">{{ r['status'] }}</span></a>{% endfor %}{% endif %}
<script>var f=document.getElementById("f"),pv=document.getElementById("prev");
function show(){pv.innerHTML="";Array.prototype.forEach.call(f.files,function(x){var i=document.createElement("img");i.src=URL.createObjectURL(x);pv.appendChild(i)})}
f.onchange=show;document.addEventListener("paste",function(e){var fl=e.clipboardData&&e.clipboardData.files;if(!fl||!fl.length)return;var dt=new DataTransfer();
Array.prototype.forEach.call(f.files,function(x){dt.items.add(x)});Array.prototype.forEach.call(fl,function(x){if(/^image\\//.test(x.type)&&dt.files.length<{{ max_files }})dt.items.add(x)});f.files=dt.files;show()});</script>{% endblock %}"""
TICKET = """{% extends 'base.html' %}{% block body %}<div class="card"><div class="top" style="margin:0"><h2 style="margin:0">#{{ t['id'] }} {{ t['title'] }}</h2>
<div class="badges"><span class="b p-{{ t['priority'] }}">{{ t['priority'] }}</span><span class="b s-{{ t['status'].split()[0] }}" id="ticket-status">{{ t['status'] }}</span></div></div>
<div class="me">{{ t['name'] }} · {{ t['sector'] }} · {{ t['category'] }} · {{ t['created']|dt }}{% if t['tech'] %} · Atendente: {{ t['tech'] }}{% endif %}</div>
<pre>{{ t['description'] or 'Sem descrição.' }}</pre>
{% if files %}<div class="imgs">{% for f in files %}<a href="{{ url_for('uploads', fn=f['filename']) }}" target="_blank"><img src="{{ url_for('uploads', fn=f['filename']) }}" alt="{{ f['orig'] }}"></a>{% endfor %}</div>{% endif %}
{% if tech %}<div class="row"><form method="post" action="{{ url_for('acao', tid=t['id'], acao='status') }}" class="row" style="margin:0"><input type="hidden" name="csrf" value="{{ csrf }}">
<select name="status">{% for s in STATUS %}<option {{ 'selected' if s==t['status'] }}>{{ s }}</option>{% endfor %}</select><button>Alterar</button></form>
<form method="post" action="{{ url_for('acao', tid=t['id'], acao='assumir') }}" style="margin:0"><input type="hidden" name="csrf" value="{{ csrf }}"><button>Assumir</button></form>
<form method="post" action="{{ url_for('acao', tid=t['id'], acao='excluir') }}" style="margin:0" onsubmit="return confirm('Excluir este chamado?')"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="dan">Excluir</button></form></div>
{% elif t['status'] != 'Resolvido' %}<form method="post" action="{{ url_for('resolver', token=t['token']) }}"><input type="hidden" name="csrf" value="{{ csrf }}"><button>Marcar como resolvido</button></form>{% endif %}</div>
<h2>Histórico <span class="me" id="sync-state">· atualização automática ativa</span></h2><div id="notes-list">{% for n in notes %}<div class="note {{ 't' if n['is_tech'] }}" data-note-id="{{ n['id'] }}">{{ n['text'] }} <small>· {{ n['author'] }} · {{ n['created']|dt }}</small></div>{% else %}<div class="me" id="empty-notes">Nenhuma nota ainda.</div>{% endfor %}</div>
<form class="row" method="post" action="{{ url_for('acao', tid=t['id'], acao='nota') if tech else url_for('nota_solic', token=t['token']) }}"><input type="hidden" name="csrf" value="{{ csrf }}">
<input name="text" placeholder="Adicionar nota" style="flex:1" required><button class="pri">Enviar</button></form>
{% if not tech %}<p class="me">Guarde este endereço para acompanhar o chamado depois.</p>{% endif %}
<script>
(function(){
  var list=document.getElementById('notes-list');
  var statusEl=document.getElementById('ticket-status');
  var syncEl=document.getElementById('sync-state');
  var lastId=0;
  list.querySelectorAll('[data-note-id]').forEach(function(n){lastId=Math.max(lastId,Number(n.dataset.noteId)||0)});
  var endpoint={{ (url_for('atualizacoes_tecnico', tid=t['id']) if tech else url_for('atualizacoes_solicitante', token=t['token']))|tojson }};
  function poll(){
    if(document.hidden)return;
    fetch(endpoint+'?after='+lastId,{cache:'no-store',headers:{'Accept':'application/json'}})
      .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json()})
      .then(function(data){
        if(statusEl && statusEl.textContent!==data.status){
          statusEl.textContent=data.status;
          statusEl.className='b s-'+data.status.split(' ')[0];
        }
        (data.notes||[]).forEach(function(n){
          if(n.id<=lastId)return;
          var item=document.createElement('div');
          item.className='note'+(n.is_tech?' t':''); item.dataset.noteId=n.id;
          item.appendChild(document.createTextNode(n.text+' '));
          var small=document.createElement('small');
          small.textContent='· '+n.author+' · '+n.created; item.appendChild(small);
          var empty=document.getElementById('empty-notes');if(empty)empty.remove();
          list.appendChild(item);lastId=n.id;
        });
        if(syncEl)syncEl.textContent='· atualizado agora';
      }).catch(function(){if(syncEl)syncEl.textContent='· tentando reconectar…'});
  }
  setInterval(poll,5000);
  document.addEventListener('visibilitychange',function(){if(!document.hidden)poll()});
})();
</script>{% endblock %}"""
PAINEL = """{% extends 'base.html' %}{% block body %}<div class="stats">
<a class="card stat" href="?"><b>{{ total }}</b><span class="me">Total</span></a>{% for s in STATUS %}<a class="card stat" href="?status={{ s }}"><b>{{ cnt.get(s,0) }}</b><span class="me">{{ s }}</span></a>{% endfor %}</div>
<form class="bar" method="get"><input name="q" value="{{ q }}" placeholder="Buscar nome, título ou número"><select name="status"><option value="">Todos os status</option>{% for s in STATUS %}<option {{ 'selected' if s==st }}>{{ s }}</option>{% endfor %}</select>
<select name="prio"><option value="">Toda prioridade</option>{% for p in PRIOS %}<option {{ 'selected' if p==pr }}>{{ p }}</option>{% endfor %}</select><button>Filtrar</button></form>
{% for r in rows %}<a class="card item" href="{{ url_for('detalhe', tid=r['id']) }}"><div><b>#{{ r['id'] }} {{ r['title'] }}</b><div class="me">{{ r['name'] }} · {{ r['sector'] }} · {{ r['category'] }} · {{ r['created']|dt }}{% if r['tech'] %} · {{ r['tech'] }}{% endif %}</div></div>
<div class="badges"><span class="b p-{{ r['priority'] }}">{{ r['priority'] }}</span><span class="b s-{{ r['status'].split()[0] }}">{{ r['status'] }}</span></div></a>{% else %}<div class="card me">Nenhum chamado encontrado.</div>{% endfor %}
<script>var last={{ mx }},lastUpdated={{ mupdated }};function beep(){try{var a=new(window.AudioContext||window.webkitAudioContext)(),o=a.createOscillator();o.connect(a.destination);o.frequency.value=880;o.start();setTimeout(function(){o.stop();a.close()},200)}catch(e){}}
function checkUpdates(){if(document.hidden)return;fetch("{{ url_for('ultimo') }}",{cache:"no-store"}).then(function(r){if(!r.ok)throw new Error("HTTP "+r.status);return r.json()}).then(function(d){if(d.max>last||d.updated>lastUpdated){var isNew=d.max>last;last=d.max;lastUpdated=d.updated;if(isNew){var t=document.getElementById("toast");t.textContent="🔔 Novo chamado";t.style.display="block";beep()}setTimeout(function(){location.reload()},isNew?1800:300)}}).catch(function(){})}
setInterval(checkUpdates,5000);document.addEventListener("visibilitychange",function(){if(!document.hidden)checkUpdates()});</script>{% endblock %}"""
LOGIN = """{% extends 'base.html' %}{% block body %}<form class="card" method="post" style="max-width:360px;margin:30px auto"><h2 style="margin-top:0">Área do técnico</h2><input type="hidden" name="csrf" value="{{ csrf }}">
<label>Senha</label><input type="password" name="password" autofocus required><div class="row"><button class="pri">Entrar</button></div></form>{% endblock %}"""
app.jinja_loader = DictLoader({"base.html": BASE, "index.html": INDEX, "ticket.html": TICKET, "painel.html": PAINEL, "login.html": LOGIN})

if __name__ == "__main__":
    if not TECH_PASSWORD:
        sys.exit("Defina a senha do técnico: set CHAMADOS_SENHA=suasenha")
    init_db()
    print(f"Chamados de TI rodando na porta {PORT}")
    try:
        from waitress import serve
        serve(app, host="0.0.0.0", port=PORT, threads=8)
    except ImportError:
        app.run(host="0.0.0.0", port=PORT)
else:
    init_db()

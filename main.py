# app.py
import os
import uuid
import datetime as dt
from functools import wraps

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

# -----------------------------------------------------------------------------
# App config
# -----------------------------------------------------------------------------
app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "smart_student_hub.db")

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY", "dev-secret-change-me")
app.config["JWT_ALG"] = "HS256"
db = SQLAlchemy(app)

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(64), unique=True, index=True, default=lambda: uuid.uuid4().hex)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default="student")  # 'student' or 'admin'
    headline = db.Column(db.String(255), default="")
    skills_csv = db.Column(db.String(1024), default="")
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

    achievements = db.relationship("Achievement", backref="user", lazy=True)

    def to_dict(self, include_email=False):
        base = {
            "id": self.id,
            "public_id": self.public_id,
            "name": self.name,
            "role": self.role,
            "headline": self.headline,
            "skills": [s for s in self.skills_csv.split(",") if s.strip()] if self.skills_csv else [],
            "created_at": self.created_at.isoformat()
        }
        if include_email:
            base["email"] = self.email
        return base


class Achievement(db.Model):
    __tablename__ = "achievements"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(120), default="General")
    date_str = db.Column(db.String(40), default="")
    proof_url = db.Column(db.String(1024), default="")
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "title": self.title,
            "category": self.category,
            "date": self.date_str,
            "proof_url": self.proof_url,
            "verified": self.verified,
            "created_at": self.created_at.isoformat()
        }

# -----------------------------------------------------------------------------
# Auth helpers
# -----------------------------------------------------------------------------
def create_token(user_id, role):
    payload = {
        "sub": user_id,
        "role": role,
        "iat": dt.datetime.utcnow(),
        "exp": dt.datetime.utcnow() + dt.timedelta(hours=8)
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm=app.config["JWT_ALG"])

def decode_token(token):
    try:
        return jwt.decode(token, app.config["SECRET_KEY"], algorithms=[app.config["JWT_ALG"]])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            payload = decode_token(parts[1])
            if payload:
                request.user = payload
                return f(*args, **kwargs)
        return jsonify({"error": "Unauthorized"}), 401
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not getattr(request, "user", None):
            return jsonify({"error": "Unauthorized"}), 401
        if request.user.get("role") != "admin":
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return wrapper

# -----------------------------------------------------------------------------
# Startup / seed
# -----------------------------------------------------------------------------
with app.app_context():
    db.create_all()
    # seed an admin for demo
    if not User.query.filter_by(email="admin@example.com").first():
        admin = User(
            email="admin@example.com",
            password_hash=generate_password_hash("admin123"),
            name="Admin",
            role="admin",
            headline="Institution Admin",
            skills_csv="Verification,Audits,Compliance"
        )
        db.session.add(admin)
        db.session.commit()

# -----------------------------------------------------------------------------
# Auth routes
# -----------------------------------------------------------------------------
@app.post("/api/auth/register")
def register():
    data = request.get_json(force=True)
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    name = data.get("name", "").strip()
    if not email or not password or not name:
        return jsonify({"error": "name, email, and password are required"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already in use"}), 409
    user = User(
        email=email,
        password_hash=generate_password_hash(password),
        name=name,
        role="student"
    )
    db.session.add(user)
    db.session.commit()
    token = create_token(user.id, user.role)
    return jsonify({"token": token, "user": user.to_dict(include_email=True)}), 201

@app.post("/api/auth/login")
def login():
    data = request.get_json(force=True)
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401
    token = create_token(user.id, user.role)
    return jsonify({"token": token, "user": user.to_dict(include_email=True)})

# -----------------------------------------------------------------------------
# Profile routes
# -----------------------------------------------------------------------------
@app.get("/api/me")
@auth_required
def me():
    user_id = request.user["sub"]
    user = User.query.get(user_id)
    return jsonify(user.to_dict(include_email=True))

@app.put("/api/me")
@auth_required
def update_me():
    user_id = request.user["sub"]
    user = User.query.get(user_id)
    data = request.get_json(force=True)
    user.name = data.get("name", user.name)
    user.headline = data.get("headline", user.headline)
    skills = data.get("skills")
    if isinstance(skills, list):
        user.skills_csv = ",".join([s.strip() for s in skills if s.strip()])
    db.session.commit()
    return jsonify(user.to_dict(include_email=True))

# -----------------------------------------------------------------------------
# Achievement routes
# -----------------------------------------------------------------------------
@app.get("/api/achievements")
@auth_required
def list_achievements():
    user_id = request.user["sub"]
    role = request.user["role"]
    # Admin can read by user_id query param
    target_user_id = request.args.get("user_id")
    if role == "admin" and target_user_id:
        target_id = int(target_user_id)
        ach = Achievement.query.filter_by(user_id=target_id).order_by(Achievement.created_at.desc()).all()
    else:
        ach = Achievement.query.filter_by(user_id=user_id).order_by(Achievement.created_at.desc()).all()
    return jsonify([a.to_dict() for a in ach])

@app.post("/api/achievements")
@auth_required
def create_achievement():
    user_id = request.user["sub"]
    data = request.get_json(force=True)
    title = data.get("title", "").strip()
    if not title:
        return jsonify({"error": "title is required"}), 400
    a = Achievement(
        user_id=user_id,
        title=title,
        category=data.get("category", "General").strip() or "General",
        date_str=data.get("date", "").strip(),
        proof_url=data.get("proof_url", "").strip(),
        verified=False
    )
    db.session.add(a)
    db.session.commit()
    return jsonify(a.to_dict()), 201

@app.post("/api/achievements/<int:ach_id>/verify")
@auth_required
@admin_required
def verify_achievement(ach_id):
    a = Achievement.query.get_or_404(ach_id)
    a.verified = True
    db.session.commit()
    return jsonify(a.to_dict())

# -----------------------------------------------------------------------------
# Admin helper
# -----------------------------------------------------------------------------
@app.get("/api/admin/user")
@auth_required
@admin_required
def admin_find_user():
    email = request.args.get("email", "").strip().lower()
    if not email:
        return jsonify({"error": "email query param required"}), 400
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user.to_dict(include_email=True))

# -----------------------------------------------------------------------------
# Public portfolio page (server-rendered HTML)
# -----------------------------------------------------------------------------
@app.get("/portfolio/<public_id>")
def public_portfolio(public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return make_response("Portfolio not found", 404)
    achievements = Achievement.query.filter_by(user_id=user.id, verified=True).order_by(Achievement.created_at.desc()).all()

    # Simple inline HTML for demo; you can replace with templates later
    skills = ", ".join([s for s in user.skills_csv.split(",") if s.strip()]) if user.skills_csv else "—"
    items_html = "".join(
        f"""
        <div class="card">
          <div class="row">
            <div><strong>Title:</strong> {a.title}</div>
            <div><strong>Category:</strong> {a.category}</div>
            <div><strong>Date:</strong> {a.date_str or "—"}</div>
            <div><strong>Proof:</strong> <a href="{a.proof_url or '#'}" target="_blank">{a.proof_url or "—"}</a></div>
            <div class="badge">Verified</div>
          </div>
        </div>
        """
        for a in achievements
    )

    html = f"""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8"/>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
      <title>{user.name} — Portfolio</title>
      <style>
        :root {{
          --bg:#0b0f19; --card:#121828; --muted:#9aa4b2; --fg:#e5e7eb; --accent:#7c3aed; --ok:#10b981;
        }}
        * {{ box-sizing: border-box; }}
        body {{ margin:0; font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; background: var(--bg); color: var(--fg); }}
        .wrap {{ max-width:900px; margin: 40px auto; padding: 0 16px; }}
        .hero {{ display:flex; flex-direction:column; gap:6px; margin-bottom:24px; }}
        .hero h1 {{ margin:0; font-size:28px; }}
        .hero .muted {{ color: var(--muted); }}
        .pill {{ display:inline-block; padding:6px 10px; background: #1f2937; border:1px solid #2a3244; border-radius:999px; margin-right:8px; margin-bottom:8px; }}
        .grid {{ display:grid; grid-template-columns: 1fr; gap:16px; }}
        @media (min-width: 720px) {{ .grid {{ grid-template-columns: 1fr 1fr; }} }}
        .card {{ background: var(--card); border:1px solid #1d2435; border-radius:12px; padding:14px; }}
        .row {{ display:flex; flex-direction:column; gap:6px; }}
        .badge {{ display:inline-block; background: #0b231a; color: #34d399; border:1px solid #14532d; border-radius:8px; padding:4px 8px; width:max-content; margin-top:6px; }}
        .link {{ color: #c4b5fd; text-decoration:none; }}
        .link:hover {{ text-decoration:underline; }}
        .hint {{ color: var(--muted); font-size:14px; }}
      </style>
    </head>
    <body>
      <div class="wrap">
        <div class="hero">
          <h1>{user.name}</h1>
          <div class="muted">{user.headline or ""}</div>
          <div class="hint">Public ID: {user.public_id}</div>
          <div style="margin-top:10px;">{"".join(f'<span class="pill">{s}</span>' for s in (skills.split(", ") if skills != "—" else [])) or '<span class="hint">No skills listed</span>'}</div>
        </div>
        <h2>Verified Achievements</h2>
        <div class="grid">
          {items_html or '<div class="card"><div class="hint">No verified achievements yet.</div></div>'}
        </div>
      </div>
    </body>
    </html>
    """
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

# -----------------------------------------------------------------------------
# Health
# -----------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)

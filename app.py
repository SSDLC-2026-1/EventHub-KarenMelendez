from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta
from typing import List, Optional, Dict

from flask import Flask, render_template, request, abort, url_for, redirect, session
from pathlib import Path
import json

from validation import validate_payment_form

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.secret_key = "dev-secret-change-me"


BASE_DIR = Path(__file__).resolve().parent
EVENTS_PATH = BASE_DIR / "data" / "events.json"
USERS_PATH = BASE_DIR / "data" / "users.json"
ORDERS_PATH = BASE_DIR / "data" / "orders.json"
CATEGORIES = ["All", "Music", "Tech", "Sports", "Business"]
CITIES = ["Any", "New York", "San Francisco", "Berlin", "London", "Oakland", "San Jose"]

MAX_FAILED_ATTEMPTS = 3
LOCKOUT_SECONDS = 300
failed_logins: Dict[str,dict] = {}

@dataclass(frozen=True)
class Event:
    id: int
    title: str
    category: str  
    city: str
    venue: str
    start: datetime
    end: datetime
    price_usd: float
    available_tickets: int
    banner_url: str
    description: str

def _user_with_defaults(u: dict) -> dict:
    u = dict(u)
    u.setdefault("role", "user")      
    u.setdefault("status", "active")  
    u.setdefault("locked_until", "") 
    return u

def get_current_user() -> Optional[dict]:
    email = session.get("user_email")
    if not email:
        return None
    return find_user_by_email(email)

@app.context_processor
def inject_user():
    return {"get_current_user": get_current_user}

def require_login():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))
    return user

def require_role(role: str):
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    if user.get("role") != role:
        abort(403)

    return user

def load_events() -> List[Event]:
    data = json.loads(EVENTS_PATH.read_text(encoding="utf-8"))
    return [
        Event(
            id=int(e["id"]),
            title=e["title"],
            category=e["category"],
            city=e["city"],
            venue=e["venue"],
            start=datetime.fromisoformat(e["start"]),
            end=datetime.fromisoformat(e["end"]),
            price_usd=float(e["price_usd"]),
            available_tickets=int(e["available_tickets"]),
            banner_url=e.get("banner_url", ""),
            description=e.get("description", ""),
        )
        for e in data
    ]


EVENTS: List[Event] = load_events()


def _parse_date(date_str: str) -> Optional[datetime]:
    """Parsea fecha estilo YYYY-MM-DD. Devuelve None si inválida."""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return None


def _safe_int(value: str, default: int = 1, min_v: int = 1, max_v: int = 10) -> int:
    """Validación simple de enteros para inputs (cantidad, etc.)."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(min_v, min(max_v, n))


def filter_events(
    q: str = "",
    city: str = "Any",
    date: Optional[datetime] = None,
    category: str = "All",
    ) -> List[Event]:
    q_norm = (q or "").strip().lower()
    city_norm = (city or "Any").strip()
    category_norm = (category or "All").strip()

    results = load_events()

    if category_norm != "All":
        results = [e for e in results if e.category == category_norm]

    if city_norm != "Any":
        results = [e for e in results if e.city == city_norm]

    if date:
        results = [
            e for e in results
            if e.start.date() == date.date()
        ]

    if q_norm:
        results = [
            e for e in results
            if q_norm in e.title.lower() or q_norm in e.venue.lower()
        ]

    results.sort(key=lambda e: e.start)
    return results


def get_event_or_404(event_id: int) -> Event:
    for e in EVENTS:
        if e.id == event_id:
            return e
    abort(404)


def load_users() -> list[dict]:
    if not USERS_PATH.exists():
        USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
        USERS_PATH.write_text("[]", encoding="utf-8")
    return json.loads(USERS_PATH.read_text(encoding="utf-8"))


def save_users(users: list[dict]) -> None:
    USERS_PATH.write_text(json.dumps(users, indent=2), encoding="utf-8")


def find_user_by_email(email: str) -> Optional[dict]:
    users = load_users()
    email_norm = (email or "").strip().lower()
    for u in users:
        if (u.get("email", "") or "").strip().lower() == email_norm:
            return u
    return None


def user_exists(email: str) -> bool:
    return find_user_by_email(email) is not None

def load_orders() -> list[dict]:
    if not ORDERS_PATH.exists():
        ORDERS_PATH.parent.mkdir(parents=True, exist_ok=True)
        ORDERS_PATH.write_text("[]", encoding="utf-8")
    return json.loads(ORDERS_PATH.read_text(encoding="utf-8"))


def save_orders(orders: list[dict]) -> None:
    ORDERS_PATH.write_text(json.dumps(orders, indent=2), encoding="utf-8")


def next_order_id(orders: list[dict]) -> int:
    return max([o.get("id", 0) for o in orders], default=0) + 1


# -----------------------------
# Rutas
# -----------------------------
@app.get("/")
def index():
    q = request.args.get("q", "")
    city = request.args.get("city", "Any")
    date_str = request.args.get("date", "")
    category = request.args.get("category", "All")

    date = _parse_date(date_str)
    events = filter_events(q=q, city=city, date=date, category=category)

    featured = events[:3] 
    upcoming = events[:6]

    return render_template(
        "index.html",
        q=q,
        city=city,
        date_str=date_str,
        category=category,
        categories=CATEGORIES,
        cities=CITIES,
        featured=featured,
        upcoming=upcoming,
    )


@app.get("/event/<int:event_id>")
def event_detail(event_id: int):
    event = next((e for e in load_events() if e.id == event_id), None)
    if not event:
        abort(404)

    similar = [e for e in EVENTS if e.category == event.category and e.id != event.id][:5]

    return render_template(
        "event_detail.html",
        event=event,
        similar=similar,
    )


@app.post("/event/<int:event_id>/buy")
def buy_ticket(event_id: int):
    event = get_event_or_404(event_id) 
    qty = _safe_int(request.form.get("qty", "1"), default=1, min_v=1, max_v=8)

    if qty > event.available_tickets:
        similar = [e for e in load_events() if e.category == event.category and e.id != event.id][:5]
        return render_template(
            "event_detail.html",
            event=event,
            similar=similar,
            buy_error="Not enough tickets available for that quantity."
        ), 400

    return redirect(url_for("checkout", event_id=event.id, qty=qty))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        registered = request.args.get("registered")
        msg = "Account created successfully. Please sign in." if registered == "1" else None
        return render_template("login.html", info_message=msg)

    email = request.form.get("email", "")
    password = request.form.get("password", "")

    field_errors = {}
    if not email.strip():
        field_errors.setdefault("email", []).append("Campo requerido.")
    if not password.strip():
        field_errors.setdefault("password", []).append("Campo requerido.")

    if field_errors:
        return render_template(
            "login.html",
            error="Por favor, corrige los campos resaltados.",
            field_errors=field_errors,
            form={"email": email},
        ), 400

    # Validar formato básico del email
    email_clean = email.strip().lower()
    if len(email_clean) > 254:
        field_errors.setdefault("email", []).append("Longitud máxima de 254 caracteres.")
    if email_clean.count("@") != 1:
        field_errors.setdefault("email", []).append("Debe contener exactamente un @.")
    if "@" in email_clean and "." not in email_clean.split("@")[1]:
        field_errors.setdefault("email", []).append("El dominio debe incluir al menos un punto.")
    if " " in email_clean:
        field_errors.setdefault("email", []).append("No debe contener espacios.")

    if field_errors:
        return render_template(
            "login.html",
            error="Formato de email inválido.",
            field_errors=field_errors,
            form={"email": email},
        ), 400

    state = failed_logins.setdefault(email, {"attempts": 0, "locked_until": None})
    now = datetime.utcnow()
    if state["locked_until"] and now < state["locked_until"]:
        remaning = state["locked_until"] - now
        mins = int(remaning.total_seconds() // 60) + 1
        return render_template(
            "login.html",
            error = f"Account locked. Try again in {mins} min.",

        ),403

    user = find_user_by_email(email)
    if not user or user.get("password") != password:
        state["attempts"] += 1
        if state["attempts"] > MAX_FAILED_ATTEMPTS:
            state["locked_until"] = now + timedelta(seconds = LOCKOUT_SECONDS)
        return render_template(
            "login.html",
            error="Invalid credentials.",
            field_errors={"email": " ", "password": " "},
            form={"email": email},
        ), 401
    state["attempts"] = 0
    state["locked_until"] = None

    session["user_email"] = (user.get("email") or "").strip().lower()

    return redirect(url_for("dashboard"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").replace(" ", "")
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    errors = {}

    # Validate full name
    full_name_clean = " ".join(full_name.split())  # collapse spaces
    if len(full_name_clean) < 2 or len(full_name_clean) > 60:
        errors.setdefault("full_name", []).append("Minimum length of 2 characters and maximum of 60.")
    if not all(c.isalpha() or c in " '-" for c in full_name_clean):
        errors.setdefault("full_name", []).append("Only letters (including accented), spaces, apostrophes, and hyphens.")

    # Validate email
    if len(email) > 254:
        errors.setdefault("email", []).append("Maximum length of 254 characters.")
    if email.count("@") != 1:
        errors.setdefault("email", []).append("Must contain exactly one @ symbol.")
    if "@" in email:
        local, domain = email.split("@")
        if not local or not domain or "." not in domain:
            errors.setdefault("email", []).append("Must have local part and domain with at least one dot.")
    if " " in email:
        errors.setdefault("email", []).append("Must not contain spaces.")

    # Validate phone
    if not phone.isdigit():
        errors.setdefault("phone", []).append("Only digits allowed.")
    if not 7 <= len(phone) <= 15:
        errors.setdefault("phone", []).append("Between 7 and 15 digits.")

    # Validate password
    if len(password) < 8 or len(password) > 64:
        errors.setdefault("password", []).append("Minimum length of 8 characters and maximum of 64.")
    if " " in password:
        errors.setdefault("password", []).append("Must not contain spaces.")
    if password.lower() == email:
        errors.setdefault("password", []).append("Cannot be the same as the email.")
    if not any(c.isupper() for c in password):
        errors.setdefault("password", []).append("Must contain at least one uppercase letter.")
    if not any(c.islower() for c in password):
        errors.setdefault("password", []).append("Must contain at least one lowercase letter.")
    if not any(c.isdigit() for c in password):
        errors.setdefault("password", []).append("Must contain at least one digit.")
    if not any(c in "!@#$%^&*()-_=+[]{}<>?" for c in password):
        errors.setdefault("password", []).append("Must contain at least one special character (e.g., !@#$%^&*()-_=+[]{}<>?).")

    if password != confirm_password:
        errors.setdefault("confirm_password", []).append("Must match the password exactly.")

    
    if errors:
        # Build bullet list with field names
        field_labels = {
            "full_name": "Full Name",
            "email": "Email",
            "phone": "Phone",
            "password": "Password",
            "confirm_password": "Confirm Password",
        }

        error_items = []
        for field, messages in errors.items():
            label = field_labels.get(field, field)
            for msg in messages:
                error_items.append(f"<li><strong>{label}:</strong> {msg}</li>")

        error_html = "<ul>" + "".join(error_items) + "</ul>"

        return render_template(
            "register.html",
            error=error_html,
            field_errors=errors,
            form={
                "full_name": full_name,
                "email": email,
                "phone": phone,
            }
        ), 400

    if user_exists(email):
        return render_template(
            "register.html",
            error="Este email ya está registrado.",
            field_errors={"email": "Ya existe."},
            form={
                "full_name": full_name,
                "email": email,
                "phone": phone,
            }
        ), 400

    users = load_users()
    next_id = (max([u.get("id", 0) for u in users], default=0) + 1)

    users.append({
        "id": next_id,
        "full_name": full_name_clean,
        "email": email,
        "phone": phone,
        "password": password,
        "role": "user",
        "status": "active",
    })

    save_users(users)

    return redirect(url_for("login", registered="1"))

@app.get("/dashboard")
def dashboard():
    user = require_login()
    if not isinstance(user, dict):
        return user  # redirect si no logueado

    paid = request.args.get("paid") == "1"

    return render_template(
        "dashboard.html",
        user_name=user.get("full_name"),
        paid=paid
    )

@app.route("/checkout/<int:event_id>", methods=["GET", "POST"])
def checkout(event_id: int):
    user = require_login()
    if not isinstance(user, dict):
        return user

    events = load_events()
    event = next((e for e in events if e.id == event_id), None)
    if not event:
        abort(404)

    qty = _safe_int(request.args.get("qty", "1"), default=1, min_v=1, max_v=8)

    service_fee = 5.00
    subtotal = event.price_usd * qty
    total = subtotal + service_fee

    if request.method == "GET":
        return render_template(
            "checkout.html",
            event=event,
            qty=qty,
            subtotal=subtotal,
            service_fee=service_fee,
            total=total,
            errors={},
            form_data={}
        )

    card_number = request.form.get("card_number", "")
    exp_date = request.form.get("exp_date", "")
    cvv = request.form.get("cvv", "")
    name_on_card = request.form.get("name_on_card", "")
    billing_email = request.form.get("billing_email", "")

    clean, errors = validate_payment_form(
        card_number=card_number,
        exp_date=exp_date,
        cvv=cvv,
        name_on_card=name_on_card,
        billing_email=billing_email
    )

    form_data = {
        "exp_date": clean.get("exp_date", ""),
        "name_on_card": clean.get("name_on_card", ""),
        "billing_email": clean.get("billing_email", ""),
        "card": clean.get("card", "")
    }

    if errors:
        return render_template(
            "checkout.html",
            event=event, qty=qty, subtotal=subtotal,
            service_fee=service_fee, total=total,
            errors=errors, form_data=form_data
        ), 400

    orders = load_orders()
    order_id = next_order_id(orders)

    orders.append({
        "id": order_id,
        "user_email": user.get("email"),
        "event_id": event.id,
        "event_title": event.title,
        "qty": qty,
        "unit_price": event.price_usd,
        "service_fee": service_fee,
        "total": total,
        "status": "PAID",
        "created_at": datetime.utcnow().isoformat(),
        "payment": form_data
    })

    save_orders(orders)

    return redirect(url_for("dashboard", paid="1"))



@app.route("/profile", methods=["GET", "POST"])
def profile():
 

    user = get_current_user()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    form = {
        "full_name": user.get("full_name", ""),
        "email": user.get("email", ""),
        "phone": user.get("phone", ""),
    }

    field_errors = {}  
    success_msg = None

    if request.method == "POST":
        full_name = request.form.get("full_name", "")
        phone = request.form.get("phone", "")

        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_new_password = request.form.get("confirm_new_password", "")

        # Validate
        field_errors = {}
        full_name_clean = " ".join(full_name.split())
        if len(full_name_clean) < 2 or len(full_name_clean) > 60:
            field_errors.setdefault("full_name", []).append("Longitud entre 2 y 60 caracteres.")
        if not all(c.isalpha() or c in " '-" for c in full_name_clean):
            field_errors.setdefault("full_name", []).append("Solo letras, espacios, apóstrofes y guiones.")

        phone_clean = phone.replace(" ", "")
        if not phone_clean.isdigit():
            field_errors.setdefault("phone", []).append("Solo dígitos.")
        if not 7 <= len(phone_clean) <= 15:
            field_errors.setdefault("phone", []).append("Entre 7 y 15 dígitos.")

        changing_password = bool(new_password.strip())
        if changing_password:
            if current_password != user.get("password"):
                field_errors.setdefault("current_password", []).append("Contraseña actual incorrecta.")
            if len(new_password) < 8 or len(new_password) > 64:
                field_errors.setdefault("new_password", []).append("Longitud entre 8 y 64 caracteres.")
            if " " in new_password:
                field_errors.setdefault("new_password", []).append("No espacios en blanco.")
            if new_password.lower() == user.get("email", "").lower():
                field_errors.setdefault("new_password", []).append("No puede ser igual al email.")
            if not any(c.isupper() for c in new_password):
                field_errors.setdefault("new_password", []).append("Al menos una mayúscula.")
            if not any(c.islower() for c in new_password):
                field_errors.setdefault("new_password", []).append("Al menos una minúscula.")
            if not any(c.isdigit() for c in new_password):
                field_errors.setdefault("new_password", []).append("Al menos un número.")
            if not any(c in "!@#$%^&*()-_=+[]{}<>?" for c in new_password):
                field_errors.setdefault("new_password", []).append("Al menos un carácter especial.")
            if new_password != confirm_new_password:
                field_errors.setdefault("confirm_new_password", []).append("Debe coincidir con la nueva contraseña.")

        if field_errors:
            return render_template(
                "profile.html",
                form={
                    "full_name": full_name,
                    "email": user.get("email", ""),
                    "phone": phone,
                },
                field_errors=field_errors,
                success_message=None,
            ), 400

        # Update
        users = load_users()
        email_norm = (user.get("email") or "").strip().lower()

        for u in users:
            if (u.get("email") or "").strip().lower() == email_norm:
                u["full_name"] = full_name_clean
                u["phone"] = phone_clean
                if changing_password:
                    u["password"] = new_password
                break

        save_users(users)

        form["full_name"] = full_name_clean
        form["phone"] = phone
        success_msg = "Perfil actualizado."

    return render_template(
        "profile.html",
        form=form,
        field_errors=field_errors,
        success_message=success_msg,
    )
@app.get("/admin/users")
def admin_users():

    user = require_role("admin")
    if not isinstance(user, dict):
        return user

    q = (request.args.get("q") or "").strip().lower()
    role = (request.args.get("role") or "all").strip().lower()
    status = (request.args.get("status") or "all").strip().lower()
    lockout = (request.args.get("lockout") or "all").strip().lower()

    users = [_user_with_defaults(u) for u in load_users()]

    if q:
        users = [
            u for u in users
            if q in (u.get("full_name","").lower()) or q in (u.get("email","").lower())
        ]

    if role != "all":
        users = [u for u in users if (u.get("role","user").lower() == role)]

    if status != "all":
        users = [u for u in users if (u.get("status","active").lower() == status)]

    if lockout != "all":
        if lockout == "locked":
            users = [u for u in users if (u.get("locked_until") or "").strip()]
        elif lockout == "not_locked":
            users = [u for u in users if not (u.get("locked_until") or "").strip()]

    users.sort(key=lambda u: (u.get("full_name","").lower(), u.get("id", 0)))

    return render_template(
        "admin_users.html",
        users=users,
        filters={"q": q, "role": role, "status": status, "lockout": lockout},
        total=len(users),
    )

@app.post("/admin/users/<int:user_id>/toggle")
def admin_toggle_user(user_id: int):
    users = load_users()
    for u in users:
        if int(u.get("id", 0)) == user_id:
            u.setdefault("status", "active")
            u["status"] = "disabled" if u["status"] == "active" else "active"
            break
    save_users(users)
    return redirect(url_for("admin_users"))

@app.post("/admin/users/<int:user_id>/role")
def admin_change_role(user_id: int):
    new_role = request.form.get("role", "user")

    users = load_users()
    for u in users:
        if int(u.get("id", 0)) == user_id:
            u["role"] = new_role
            break
    save_users(users)
    return redirect(url_for("admin_users"))

if __name__ == "__main__":
    app.run(debug=True)

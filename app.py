# app.py
import os
import uuid
import datetime
from functools import wraps
import smtplib
from email.message import EmailMessage
import secrets
import string

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError
from bson.objectid import ObjectId

from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(
	__name__,
	template_folder=os.path.join(BASE_DIR, "templates"),
	static_folder=os.path.join(BASE_DIR, "static")
)
print("Jinja search paths:", app.jinja_loader.searchpath)
app.secret_key = SECRET_KEY
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database
client = MongoClient(MONGO_URI)
db = client["civic_engagement"]
users_col = db["Users"]
issues_col = db["Issues"]
comments_col = db["Comments"]
upvotes_col = db["Upvotes"]

# Indexes
upvotes_col.create_index([("issue_id", ASCENDING), ("user_id", ASCENDING)], unique=True)
issues_col.create_index([("created_at", DESCENDING)])
issues_col.create_index([("status", ASCENDING), ("category", ASCENDING)])
comments_col.create_index([("issue_id", ASCENDING), ("created_at", DESCENDING)])
users_col.create_index([("email", ASCENDING)], unique=True)

# Auth
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

#otp
otps_col = db["EmailOTPs"]
otps_col.create_index([("email", ASCENDING)], name="email_idx")
otps_col.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)

class User(UserMixin):
	def __init__(self, user_doc):
		self.id = str(user_doc["_id"])
		self.email = user_doc["email"]
		self.role = user_doc.get("role", "Citizen")
	def is_admin(self):
		return self.role == "Admin"

@login_manager.user_loader
def load_user(user_id):
	user_doc = users_col.find_one({"_id": ObjectId(user_id)})
	return User(user_doc) if user_doc else None

def role_required(required_role):
	def wrapper(func):
		@wraps(func)
		def decorated_view(*args, **kwargs):
			if not current_user.is_authenticated:
				return login_manager.unauthorized()
			if required_role == "Citizen" and current_user.role not in ("Citizen", "Admin"):
				flash("Insufficient permissions.", "danger")
				return redirect(url_for("home"))
			if required_role == "Admin" and current_user.role != "Admin":
				flash("Admin access required.", "danger")
				return redirect(url_for("home"))
			return func(*args, **kwargs)
		return decorated_view
	return wrapper

# Bootstrap admin (optional via env)
def bootstrap_admin():
	if ADMIN_EMAIL and ADMIN_PASSWORD:
		existing = users_col.find_one({"email": ADMIN_EMAIL})
		if not existing:
			users_col.insert_one({
				"email": ADMIN_EMAIL,
				"password_hash": generate_password_hash(ADMIN_PASSWORD),
				"role": "Admin",
				"created_at": datetime.datetime.now(datetime.UTC)
			})
bootstrap_admin()

# Helpers
def allowed_file(filename):
	return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def save_upload(file_storage):
	if not file_storage or file_storage.filename.strip() == "":
		return None
	if not allowed_file(file_storage.filename):
		return None
	filename = secure_filename(file_storage.filename)
	unique_name = f"{uuid.uuid4().hex}_{filename}"
	path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
	file_storage.save(path)
	return unique_name

def get_admin_users():
	admins = list(users_col.find({"role": "Admin"}, {"email": 1}))
	return [{"_id": str(u["_id"]), "email": u["email"]} for u in admins]

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
	return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# Routes
@app.route("/")
def home():
	return render_template("home.html")

@app.route("/login", methods=["GET", "POST"])
def login():
	if request.method == "POST":
		email = request.form.get("email", "").strip().lower()
		password = request.form.get("password", "")
		user_doc = users_col.find_one({"email": email})
		if user_doc and check_password_hash(user_doc["password_hash"], password):
			login_user(User(user_doc))
			flash("Welcome back!", "success")
			return redirect(url_for("home"))
		flash("Invalid credentials.", "danger")
	return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
	if request.method == "POST":
		email = request.form.get("email", "").strip().lower()
		password = request.form.get("password", "")
		confirm = request.form.get("confirm", "")
		if not email or not password or password != confirm:
			flash("Please provide a valid email and matching passwords.", "warning")
			return render_template("signup.html")
		try:
			users_col.insert_one({
				"email": email,
				"password_hash": generate_password_hash(password),
				"role": "Citizen",
				"created_at": datetime.datetime.now(datetime.UTC)
			})
			user_doc = users_col.find_one({"email": email})
			login_user(User(user_doc))
			flash("Account created.", "success")
			return redirect(url_for("home"))
		except DuplicateKeyError:
			flash("Email already registered.", "danger")
	return render_template("signup.html")

@app.route("/logout")
@login_required
def logout():
	logout_user()
	flash("Logged out.", "info")
	return redirect(url_for("home"))

@app.route("/report", methods=["GET", "POST"])
@login_required
@role_required("Citizen")
def report_issue():
	if request.method == "POST":
		title = request.form.get("title", "").strip()
		description = request.form.get("description", "").strip()
		category = request.form.get("category", "").strip()
		location_text = request.form.get("location_text", "").strip()
		latitude = request.form.get("latitude")
		longitude = request.form.get("longitude")
		urgency = request.form.get("urgency", "Normal")
		photo = request.files.get("photo")
		photo_name = save_upload(photo)

		assigned_to = request.form.getlist("assigned_to")
		assigned_ids = []
		for sid in assigned_to:
			try:
				assigned_ids.append(ObjectId(sid))
			except Exception:
				pass

		if not title or not description or not category:
			flash("Title, description, and category are required.", "warning")
			return render_template("report.html", admins=get_admin_users())

		issue_doc = {
			"title": title,
			"description": description,
			"category": category,
			"location_text": location_text,
			"location": {
				"lat": float(latitude) if latitude else None,
				"lng": float(longitude) if longitude else None
			},
			"photo": photo_name,
			"status": "Reported",
			"urgency": urgency,
			"author_id": ObjectId(current_user.id),
			"assigned_official_ids": assigned_ids,
			"actions": [
				{
					"actor_id": ObjectId(current_user.id),
					"actor_role": "Citizen",
					"note": "Issue reported",
					"status": "Reported",
					"photo": photo_name,
					"created_at": datetime.datetime.utcnow()
				}
			],
			"created_at": datetime.datetime.utcnow(),
			"updated_at": datetime.datetime.utcnow(),
			"resolution_notes": None,
			"resolution_photo": None,
			"resolved_at": None
		}
		issues_col.insert_one(issue_doc)
		flash("Issue reported and tagged.", "success")
		return redirect(url_for("dashboard"))

	# GET
	return render_template("report.html", admins=get_admin_users())
def build_issue_filters(args):
	query = {}
	text = args.get("q", "").strip()
	if text:
		query["$or"] = [
			{"title": {"$regex": text, "$options": "i"}},
			{"description": {"$regex": text, "$options": "i"}},
			{"location_text": {"$regex": text, "$options": "i"}}
		]
	category = args.get("category", "").strip()
	if category:
		query["category"] = category
	status = args.get("status", "").strip()
	if status:
		query["status"] = status
	return query

def fetch_issues_with_upvotes(query, sort_field="created_at", sort_dir=-1, limit=50):
	pipeline = [
		{"$match": query},
		{"$sort": {sort_field: sort_dir}},
		{"$limit": limit},
		{"$lookup": {
			"from": "Upvotes",
			"localField": "_id",
			"foreignField": "issue_id",
			"as": "upvote_docs"
		}},
		{"$addFields": {"upvotes_count": {"$size": "$upvote_docs"}}},
		{"$project": {"upvote_docs": 0}}
	]
	return list(issues_col.aggregate(pipeline))

@app.route("/dashboard")
def dashboard():
	query = build_issue_filters(request.args)
	mine = request.args.get("mine")
	if mine == "1" and current_user.is_authenticated:
		query["assigned_official_ids"] = {"$in": [ObjectId(current_user.id)]}
	issues = fetch_issues_with_upvotes(query)
	return render_template("dashboard.html", issues=issues, args=request.args)

@app.route("/feed")
def feed():
	# Reuse your filter builder so search/category/status work if you add query params
	query = build_issue_filters(request.args)

	# Get issues with upvote counts using your existing helper
	issues = fetch_issues_with_upvotes(query, sort_field="created_at", sort_dir=-1, limit=200)

	# Compute sort variants
	def urgency_score(u):
		order = {"Critical": 3, "High": 2, "Normal": 1, "Low": 0}
		return order.get((u or "Normal"), 1)

	sort_mode = request.args.get("sort", "hot")  # hot | top | new | urgent

	if sort_mode == "top":
		issues.sort(key=lambda i: (i.get("upvotes_count", 0), i.get("created_at")), reverse=True)
	elif sort_mode == "urgent":
		issues.sort(key=lambda i: (urgency_score(i.get("urgency")), i.get("upvotes_count", 0), i.get("created_at")), reverse=True)
	elif sort_mode == "new":
		issues.sort(key=lambda i: i.get("created_at"), reverse=True)
	else:  # hot: urgency first, then upvotes, then recency
		issues.sort(key=lambda i: (urgency_score(i.get("urgency")), i.get("upvotes_count", 0), i.get("created_at")), reverse=True)

	return render_template("feed.html", issues=issues, args=request.args, sort=sort_mode)

@app.route("/issue/<issue_id>")
def issue_detail(issue_id):
	issue = issues_col.find_one({"_id": ObjectId(issue_id)})
	if not issue:
		flash("Issue not found.", "warning")
		return redirect(url_for("dashboard"))

	upvotes_count = upvotes_col.count_documents({"issue_id": issue["_id"]})
	comments = list(comments_col.find({"issue_id": issue["_id"]}).sort("created_at", DESCENDING))

	assigned_ids = issue.get("assigned_official_ids", []) or []
	assigned_admins = []
	if assigned_ids:
		assigned_admins = list(users_col.find({"_id": {"$in": assigned_ids}}, {"email": 1}))

	actions = issue.get("actions", [])

	return render_template(
		"issue_detail.html",
		issue=issue,
		upvotes_count=upvotes_count,
		comments=comments,
		assigned_admins=assigned_admins,
		actions=actions
	)

@app.route("/issue/<issue_id>/action", methods=["POST"])
@login_required
@role_required("Admin")
def add_issue_action(issue_id):
	note = request.form.get("note", "").strip()
	photo = request.files.get("photo")
	photo_name = save_upload(photo)
	action = {
		"actor_id": ObjectId(current_user.id),
		"actor_role": "Admin",
		"note": note if note else None,
		"photo": photo_name,
		"status": None,
		"created_at": datetime.datetime.utcnow()
	}
	issues_col.update_one(
		{"_id": ObjectId(issue_id)},
		{"$push": {"actions": action}, "$set": {"updated_at": datetime.datetime.utcnow()}}
	)
	flash("Action update added.", "success")
	return redirect(url_for("issue_detail", issue_id=issue_id))

@app.route("/issue/<issue_id>/upvote", methods=["POST"])
@login_required
def upvote_issue(issue_id):
	issue_obj_id = ObjectId(issue_id)
	try:
		upvotes_col.insert_one({
			"issue_id": issue_obj_id,
			"user_id": ObjectId(current_user.id),
			"created_at": datetime.datetime.now(datetime.UTC)
		})
	except DuplicateKeyError:
		flash("You already upvoted this issue.", "info")
		return redirect(request.referrer or url_for("issue_detail", issue_id=issue_id))
	flash("Upvoted.", "success")
	return redirect(request.referrer or url_for("issue_detail", issue_id=issue_id))

@app.route("/issue/<issue_id>/comment", methods=["POST"])
@login_required
def comment_issue(issue_id):
	text = request.form.get("text", "").strip()
	if not text:
		flash("Comment cannot be empty.", "warning")
		return redirect(url_for("issue_detail", issue_id=issue_id))
	comments_col.insert_one({
		"issue_id": ObjectId(issue_id),
		"user_id": ObjectId(current_user.id),
		"text": text,
		"created_at": datetime.datetime.now(datetime.UTC)
	})
	flash("Comment added.", "success")
	return redirect(url_for("issue_detail", issue_id=issue_id))

@app.route("/admin", methods=["GET"])
@login_required
@role_required("Admin")
def admin_panel():
	query = build_issue_filters(request.args)
	sort_by = request.args.get("sort", "created_at")
	sort_dir = DESCENDING if request.args.get("dir", "desc") == "desc" else ASCENDING
	sort_field = {
		"created_at": "created_at",
		"upvotes": "upvotes_count",
		"status": "status",
		"urgency": "urgency"
	}.get(sort_by, "created_at")
	issues = fetch_issues_with_upvotes(query, sort_field=sort_field, sort_dir=-1 if sort_dir == DESCENDING else 1, limit=200)

	# Metrics
	total = issues_col.count_documents({})
	resolved = issues_col.count_documents({"status": "Resolved"})
	pending = total - resolved
	resolved_pct = round((resolved / total) * 100, 1) if total else 0.0

	avg_resolution_days = None
	resolved_docs = issues_col.find({"status": "Resolved", "resolved_at": {"$ne": None}}, {"created_at": 1, "resolved_at": 1})
	deltas = []
	for d in resolved_docs:
		deltas.append((d["resolved_at"] - d["created_at"]).total_seconds() / 86400.0)
	if deltas:
		avg_resolution_days = round(sum(deltas) / len(deltas), 2)

	return render_template("admin.html",
		issues=issues,
		args=request.args,
		metrics={"total": total, "resolved_pct": resolved_pct, "pending": pending, "avg_resolution_days": avg_resolution_days}
	)

@app.route("/admin/issue/<issue_id>/update", methods=["POST"])
@login_required
@role_required("Admin")
def admin_update_issue(issue_id):
	status = request.form.get("status", "Reported")
	urgency = request.form.get("urgency", "Normal")
	notes = request.form.get("resolution_notes", "").strip()
	photo = request.files.get("resolution_photo")
	photo_name = save_upload(photo)

	action = {
		"actor_id": ObjectId(current_user.id),
		"actor_role": "Admin",
		"note": notes if notes else None,
		"photo": photo_name,
		"status": status,
		"created_at": datetime.datetime.utcnow()
	}

	update_doc = {
		"status": status,
		"urgency": urgency,
		"resolution_notes": notes if notes else None,
		"updated_at": datetime.datetime.utcnow()
	}
	if status == "Resolved":
		update_doc["resolved_at"] = datetime.datetime.utcnow()
	if photo_name:
		update_doc["resolution_photo"] = photo_name

	issues_col.update_one(
		{"_id": ObjectId(issue_id)},
		{"$set": update_doc, "$push": {"actions": action}}
	)
	flash("Issue updated.", "success")
	return redirect(url_for("admin_panel"))

# Analytics APIs
@app.route("/analytics")
def analytics():
	return render_template("analytics.html")

@app.route("/api/analytics/summary")
def api_analytics_summary():
	total = issues_col.count_documents({})
	resolved = issues_col.count_documents({"status": "Resolved"})
	reported = issues_col.count_documents({"status": {"$ne": "Resolved"}})
	return jsonify({"total": total, "resolved": resolved, "reported": reported})

@app.route("/api/analytics/time-series")
def api_time_series():
	# Monthly reported and resolved counts for last 12 months
	now = datetime.datetime.now(datetime.UTC)
	start = (now.replace(day=1) - datetime.timedelta(days=365)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
	pipeline_reported = [
		{"$match": {"created_at": {"$gte": start}}},
		{"$group": {"_id": {"y": {"$year": "$created_at"}, "m": {"$month": "$created_at"}}, "count": {"$sum": 1}}},
		{"$sort": {"_id.y": 1, "_id.m": 1}}
	]
	pipeline_resolved = [
		{"$match": {"resolved_at": {"$ne": None, "$gte": start}}},
		{"$group": {"_id": {"y": {"$year": "$resolved_at"}, "m": {"$month": "$resolved_at"}}, "count": {"$sum": 1}}},
		{"$sort": {"_id.y": 1, "_id.m": 1}}
	]
	rep = list(issues_col.aggregate(pipeline_reported))
	res = list(issues_col.aggregate(pipeline_resolved))
	def expand(series):
		by_key = {f"{d['_id']['y']}-{d['_id']['m']:02d}": d["count"] for d in series}
		labels = []
		data = []
		cur = start
		for _ in range(13):
			key = f"{cur.year}-{cur.month:02d}"
			labels.append(key)
			data.append(by_key.get(key, 0))
			# next month
			year = cur.year + (1 if cur.month == 12 else 0)
			month = 1 if cur.month == 12 else cur.month + 1
			cur = cur.replace(year=year, month=month)
		return labels, data
	labels, reported_counts = expand(rep)
	_, resolved_counts = expand(res)
	return jsonify({"labels": labels, "reported": reported_counts, "resolved": resolved_counts})

@app.route("/api/analytics/categories")
def api_categories():
	pipeline = [
		{"$group": {"_id": "$category", "count": {"$sum": 1}}},
		{"$sort": {"count": -1}}
	]
	rows = list(issues_col.aggregate(pipeline))
	return jsonify({"labels": [r["_id"] or "Unknown" for r in rows], "data": [r["count"] for r in rows]})

@app.route("/api/analytics/areas")
def api_areas():
	pipeline = [
		{"$group": {"_id": "$location_text", "count": {"$sum": 1}}},
		{"$sort": {"count": -1}},
		{"$limit": 10}
	]
	rows = list(issues_col.aggregate(pipeline))
	return jsonify({"labels": [r["_id"] or "Unknown" for r in rows], "data": [r["count"] for r in rows]})

if __name__ == "__main__":
	app.run(host="127.0.0.1", port=5000, debug=True)
from flask import Flask, request, session, render_template, redirect, url_for
from werkzeug.utils import secure_filename  # For file uploads
from functools import wraps  # For decorators

import joblib
import numpy as np
import os


fake_users = {}

app = Flask(__name__)


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped_view


# Secret key for sessions (login)
app.secret_key = "bomradar_secret_key"

# Load the trained model
model_path = "model/bomradar_fraud_model.pkl"


if os.path.exists(model_path):
    ai_fraud_model = joblib.load(model_path)
else:
    ai_fraud_model = None


# authentication routes
@app.route("/", methods=["GET"])
def splash():
    return render_template("splash.html", user=None)


@app.route("/welcome")
def welcome():
    return render_template("welcome.html", user=None)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "user" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        first_name = request.form.get("first_name")
        surname = request.form.get("surname")
        profile_pic = request.files.get("profile_pic")
        confirm_password = request.form["confirm_password"]

        # Checking if email already exists
        if email in fake_users:
            return render_template("auth/signup.html", error="Email already registered")

        # Checking if passwords match
        if password != confirm_password:
            return render_template("auth/signup.html", error="Passwords do not match")

        # Save user to fake database
        fake_users[email] = {
            "first_name": first_name,
            "surname": surname,
            "email": email,
            "password": password,
            "profile_pic": profile_pic,
            "balance": 500000,  # starting balance (TL)
            "fraud_alerts": 0,
            "profile_pic": None,  # Placeholder for profile picture filename
            "transactions": [],
        }

        return redirect(url_for("login"))

    return render_template("auth/signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = fake_users.get(email)

        if user and user["password"] == password:
            session["user"] = email  # store user email in session
            return redirect(url_for("home"))
        else:
            return render_template("auth/login.html", error="Invalid email or password")
    return render_template("auth/login.html")


# logout route
@app.route("/logout")
def logout():
    session.clear()  # removes all user data from session
    return redirect(url_for("welcome"))


# Dashboard routes
@app.route("/home")
@login_required
def home():
    email = session.get("user")
    # get user email from session

    # Check if email is actually a dict and extract the email string
    if isinstance(email, dict):
        email = email.get("email", "")

    # Ensure email is a string
    if not isinstance(email, str) or email not in fake_users:
        session.clear()
        return redirect(url_for("login"))

    if email not in fake_users:
        session.clear()
        return redirect(url_for("login"))

    user = fake_users[email]  # get user data from fake database
    # Slice last 5 transactions
    last_five = user["transactions"][-5:] if user["transactions"] else []

    return render_template("dashboard/home.html", user=user, transactions=last_five)


@app.route("/send", methods=["GET", "POST"])
@login_required
def send_money():

    email = session["user"]  # get user email from session
    if email not in fake_users:
        session.clear()
        return redirect(url_for("login"))

    current_user = fake_users[email]  # get user data from fake database

    if request.method == "POST":
        recipient = request.form["recipient"]
        amount = float(request.form["amount"])
        purpose = request.form["purpose"]

        # 1️⃣ RULE-BASED FRAUD CHECKS
        # ----------------------------

        # Rule 1: Insufficient funds - Cannot send more than balance
        if amount > current_user["balance"]:  # current logged in user balance
            return render_template(
                "result.html",
                status="danger",
                message="❌ Transaction failed. Insufficient balance.",
            )

        # Rule 2: Suspicious large transfer (account draining)
        if amount >= 0.9 * current_user["balance"]:
            current_user["fraud_alerts"] += 1  # increment fraud alerts
            current_user["transactions"].append(
                {
                    "recipient": recipient,
                    "amount": amount,
                    "purpose": purpose,
                    "status": "Fraud Blocked",
                }
            )

            return render_template(
                "result.html",
                status="danger",
                message="⚠️ Transaction blocked. Suspicious high-value transfer detected.",
            )

        # ----------------------------
        # 2️⃣ AI-BASED FRAUD CHECK
        # ----------------------------

        if ai_fraud_model is None:
            return render_template(
                "result.html",
                status="danger",
                message="⚠️ AI model not loaded.",
            )

        # ---- SIMULATED TRANSACTION FEATURES(This is a placeholder for actual features) ----

        transaction = np.random.normal(0, 1, 30)  # Random values for other features

        # ---- Fraud probability based on amount ----
        if amount < 50000:  # 5,000 Turkish Lira
            fraud_chance = 0.01  # 1% chance of fraud for small amounts
        elif amount < 200000:
            fraud_chance = 0.05  # 5% chance of fraud for medium amounts
        elif amount < 500000:
            fraud_chance = 0.25  # 25% chance of fraud for large amounts
        else:
            fraud_chance = 0.45  # 45% chance of fraud for very large amounts

        # Random decision: should this look like fraud?
        if np.random.rand() < fraud_chance:
            transaction[14] = -10  # V14 (strong fraud indicator)
            transaction[12] = -7  # V12
            transaction[4] = 6  # V4

        transaction[-1] = amount  # Amount feature

        # AI prediction
        prediction = ai_fraud_model.predict(transaction.reshape(1, -1))[
            0
        ]  # used to turn transaction into 2D array

        if prediction == 1:
            current_user["fraud_alerts"] += 1

            current_user["transactions"].append(
                {
                    "recipient": recipient,
                    "amount": amount,
                    "purpose": purpose,
                    "status": "Fraud Blocked",
                }
            )

            return render_template(
                "result.html",
                status="danger",
                message="⚠️ Transaction blocked by AI. Suspicious activity detected.",
            )

        # If all checks passed, process the transaction
        current_user["balance"] -= amount

        current_user["transactions"].append(
            {
                "recipient": recipient,
                "amount": amount,
                "purpose": purpose,
                "status": "Success",
            }
        )

        return render_template(
            "result.html",
            status="success",
            message="✅ Transaction successful.",
        )

    return render_template("dashboard/send_money.html")


@app.route("/history")
@login_required
def history():
    email = session["user"]
    if email not in fake_users:
        session.clear()
        return redirect(url_for("login"))

    user = fake_users[email]
    return render_template(
        "dashboard/history.html", user=user, transactions=user["transactions"]
    )


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    email = session["user"]
    if email not in fake_users:
        session.clear()
        return redirect(url_for("login"))

    user = fake_users[email]

    if request.method == "POST":
        username = request.form.get("username")

        if username:
            session["username"] = username

        file = request.files.get("profile_pic")
        if file and file.filename != "":
            filename = secure_filename(file.filename)
            upload_path = os.path.join("static/uploads", filename)
            file.save(upload_path)
            session["profile_pic"] = filename

    return render_template("dashboard/profile.html", user=user)


@app.route("/help")
@login_required
def help_page():
    email = session["user"]
    user = fake_users[email]
    return render_template("dashboard/help.html", user=user)


if __name__ == "__main__":
    app.run(debug=True)

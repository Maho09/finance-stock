import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_data = db.execute(
        "SELECT logbook.stock, logbook.shares, logbook.current_price, logbook.total FROM logbook WHERE user_name = ?", session["user_name"])
    
    for row in user_data:
        look = lookup(row["stock"]) 
        total = look["price"] * row["shares"]
        db.execute("update logbook set current_price = ? , total = ? where user_name = ? and stock = ?", look["price"], total,  session["user_name"], row["stock"])
    
    cash = db.execute("SELECT cash FROM users WHERE username = ?", session["user_name"])
    totals = db.execute("SELECT total FROM logbook WHERE user_name = ?", session["user_name"])
    total_value = float(cash[0]["cash"])
    for row in totals:
        total_value += row["total"]
    return render_template("index.html", user_data=user_data, cash=cash, total_value=total_value)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")
        s_check = int(shares.isnumeric())
        if not s_check:
            return apology("invalid symbol")
        quote = lookup(symbol)
        if not symbol or not quote:
            return apology("invalid symbol")
        stock_price = float(quote["price"])
        total_price = stock_price * int(shares)
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        if int(total_price) > cash[0]["cash"]:
            return apology("insufficient cash")
        if int(shares) <= 0:
            return apology("invalid number of shares")
        db.execute("INSERT INTO history (user_name,stock,price,Action, shares) VALUES (?, ?, ?, ?, ?)",

                   session["user_name"], symbol, total_price, "BUY", shares)
        check = db.execute("SELECT * from logbook WHERE user_name = ? AND stock = ?", session["user_name"], symbol)
        if len(check) == 0:
            total1 = int(shares) * stock_price
            db.execute("INSERT INTO logbook (user_name,stock,shares,current_price, total) VALUES (?, ?, ?, ?, ?)",

                       session["user_name"], symbol, shares, stock_price, total1)
        else:
            shares1 = db.execute("SELECT shares FROM logbook WhERE user_name = ? AND stock = ?", session["user_name"], symbol)
            new_shares = int(shares1[0]["shares"]) + int(shares)
            total = new_shares * stock_price
            db.execute("UPDATE logbook SET shares = ? , current_price = ?, total = ? WHERE user_name = ? AND stock = ?",

                       new_shares, stock_price, total, session["user_name"], symbol)
        new_balance = float(cash[0]["cash"] - float(total_price))
        db.execute("UPDATE users set cash = ? where id = ?", new_balance, session["user_id"])
        casho = db.execute("SELECT cash FROM users WHERE username = ?", session["user_name"])
        return render_template("bought.html", casho=casho, total_price=total_price)

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT * FROM history WHERE user_name = ?", session["user_name"])
    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["user_name"] = rows[0]["username"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        quote = lookup(symbol)
        if not symbol or not quote:
            return apology("invalid symbol")

        return render_template("quoted.html", quote=quote)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        user_name = request.form.get("username")
        password = request.form.get("password")
        password1 = request.form.get("confirmation")
        check = db.execute("select username FROM users WHERE username= ?", user_name)
        if not user_name or check:
            return apology("invalid username")
        elif not password:
            return apology("invalid empty password")
        elif password != password1:
            return apology("passwords don't match")
        hashed = generate_password_hash(password)
        db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", user_name, hashed)
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        quote = lookup(symbol)
        if not symbol or not quote:
            return apology("select a stock")
        shares1 = db.execute("SELECT shares FROM logbook WhERE user_name = ? AND stock = ?", session["user_name"], symbol)
        if int(shares) > int(shares1[0]["shares"]):
            return apology("Insufficient Shares")
        if int(shares) <= 0:
            return apology("can't sell ZERO shares")
        stock_price = float(quote["price"])
        total_price = float(stock_price * float(shares))
        db.execute("INSERT INTO history (user_name,stock,price,Action, shares) VALUES (?, ?, ?, ?, ?)",

                   session["user_name"], symbol, total_price, "SELL", shares)
        check = db.execute("SELECT * from logbook WHERE user_name = ? AND stock = ?", session["user_name"], symbol)

        if len(check) != 0:
            new_shares = int(shares1[0]["shares"]) - int(shares)
            total = float(new_shares * stock_price)
            db.execute("UPDATE logbook SET shares = ? , current_price = ?, total = ? WHERE user_name = ? AND stock = ?",

                       new_shares, stock_price, total, session["user_name"], symbol)

        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        new_balance = cash[0]["cash"] + total_price
        db.execute("UPDATE users set cash = ? where id = ?", new_balance, session["user_id"])

        shares2 = db.execute("SELECT shares FROM logbook WhERE user_name = ? AND stock = ?", session["user_name"], symbol)
        if int(shares2[0]["shares"]) == 0:
            db.execute("delete from logbook where stock = ? and user_name = ?", symbol, session["user_name"])

        return redirect("/")
    else:
        stocks_owned = db.execute("SELECT stock FROM logbook WHERE user_name = ?", session["user_name"])
        return render_template("sell.html", stocks_owned=stocks_owned)


@app.route("/new_password", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "POST":
        password = request.form.get("password")
        if not password:
            return apology("NEW Password REQUIRED")
        old_hash = db.execute("SELECT hash FROM users WHERE username = ?", session["user_name"])
        hashed1 = generate_password_hash(password)
        if check_password_hash(old_hash[0]["hash"], password):
            return apology("don't use the same old password")

        db.execute("UPDATE users SET hash = ? WHERE username = ?", hashed1, session["user_name"])
        return redirect("/")
    else:
        return render_template("pass.html")
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure responses aren't cached
if app.config["DEBUG"]:
    @app.after_request
    def after_request(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = 0
        response.headers["Pragma"] = "no-cache"
        return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():

    # Obtain matrix from transaction table summing share amounts by stock name
    rows = db.execute("SELECT name, SUM(shares) AS shares FROM transactions WHERE id = :userid GROUP BY name",
                      userid=session["user_id"])

    # If matrix is null (user has no stock transactions)
    if rows is None:
        return apology("Get to trading!")

    # Dictionary to store
    indexdict = []

    # Totalholdingval will store the total value of the account
    totalholdingval = 0

    # Iterate through rows in queried table (see above)
    for row in rows:
        symbol = row["name"]
        shares = row["shares"]
        quote = lookup(symbol)
        # Append objects to dictionary
        indexdict.append({"symbol": symbol, "shares": shares,
                          "price": quote["price"], "totalval": quote["price"] * shares})
        totalholdingval += quote["price"] * shares

    # Store user's cash balance in cashbalance
    cashbalance = db.execute("SELECT cash FROM users WHERE id = :userid",
                             userid=session["user_id"])

    # Add the amount of cash left in account
    totalholdingval = totalholdingval + cashbalance[0]["cash"]

    return render_template("index.html", indexdict=indexdict, cashbalance=cashbalance[0]["cash"], totalholdingval=totalholdingval)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Store stock symbol from form in symbol
        symbol = request.form.get("symbol")

        # Check that symbol is not blank
        if symbol == "":
            return apology("Please input a symbol")

        # Check for fractional, negative, and non-numeric shares
        if not request.form.get("shares").isdigit():
            return apology("Please input valid number")

        # Store # of shares to buy from form in shares
        shares = int(request.form.get("shares"))

        # Store values returned from lookup in quote
        quote = lookup(symbol)

        # If lookup function doesn't return properly, display apology
        if not quote:
            return apology("Stock doesn't exist")

        # Access the price of stock, 2nd element of quote tuple
        price = quote["price"]
        name = quote["name"]

        # Moneyneeded to buy stock = price *
        moneyneeded = price * shares

        # Access rows from users table that store user's cash amount
        rows = db.execute("SELECT cash FROM users WHERE id = :userid",
                          userid=session["user_id"])

        # Store user's cash amount left in moneyleft
        moneyleft = rows[0]["cash"]

        # If user can buy stock
        if moneyneeded < moneyleft:
            # Insert a transaction into transactions table
            db.execute("INSERT INTO transactions (id, name, price, shares) VALUES (:userid, :name, :price, :shares)",
                       userid=session["user_id"], name=name, price=price, shares=shares)
            # Update cash amount in users table
            db.execute("UPDATE users SET cash = cash - :moneyneeded WHERE id = :userid",
                       moneyneeded=moneyneeded, userid=session["user_id"])

        # If user cannot buy stock, return apology
        else:
            return apology("Not enough money in account for this transaction")

        # Redirect user to homepage
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():

    # Obtain transaction table
    rows = db.execute("SELECT name, price, shares, date FROM transactions WHERE id = :userid",
                      userid=session["user_id"])

    # If matrix is null (user has no stock transactions)
    if rows is None:
        return apology("Get to trading!")

    # Create a dictionary to store values for our table in history.html
    history = []

    # Iterate through the cells from the SQL Query row by row and store values in our new dictionary variables
    for row in rows:
        symbol = row["name"]
        price = row["price"]
        shares = int(row["shares"])
        date = row["date"]
        # If we have a positive value of shares, it is a buy transaction
        if shares > 0:
            history.append({"symbol": symbol, "transacttype": 'buy',
                            "shares": shares, "price": price, "date": date})
        # If we have a negative value of shares, it is a sell transaction
        if shares < 0:
            shares = -shares
            history.append({"symbol": symbol, "transacttype": 'sell',
                            "shares": shares, "price": price, "date": date})

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
            return apology("must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Store symbol inputted from form into symbol
        symbol = request.form.get("symbol")

        # Store lookup function value in quote
        quote = lookup(symbol)

        # If inputted symbol does not exist
        if not quote:
            return apology("Stock doesn't exist")

        # If stock exists, output quote values on quoted.html
        else:
            return render_template("quoted.html", quote=quote)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # Ensure confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide confirmation")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Check if username exists
        if len(rows) != 0:
            return apology("username exists")

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Check that password matches confirmation
        if password != confirmation:
            return apology("password does not match confirmation")

        # Encrypt the password though a hash generator. Store result in variable passhash
        # http://werkzeug.pocoo.org/docs/0.12/utils/#werkzeug.security.generate_password_hash
        passhash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # Insert new username and password into database
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :passhash)",
                   username=username, passhash=passhash)

        return redirect("/")

    # User reached route via GET
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Store stock symbol from form in symbol
        symbol = request.form.get("symbol")
        # Check that symbol is not blank
        if symbol == "":
            return apology("Please input a symbol")

        # Check for fractional, negative, and non-numeric shares
        if not request.form.get("shares").isdigit():
            return apology("Please input valid number")

        # Store # of shares to buy from form in shares
        shares = int(request.form.get("shares"))

        # Store values returned from lookup in quote
        quote = lookup(symbol)
        # If lookup function doesn't return properly, display apology
        if not symbol:
            return apology("Stock doesn't exist")

        # Access the price of stock
        price = quote["price"]
        name = quote["name"]

        # Moneygained from selling stock = price * # of shares
        moneygained = price * shares

        # Access rows from users table that store user's cash amount
        rows = db.execute("SELECT cash FROM users WHERE id = :userid",
                          userid=session["user_id"])

        # Store user's cash amount left in moneyleft
        moneyleft = rows[0]["cash"]

        # Access rows from transactions table that store users portfolio
        rows = db.execute("SELECT name, SUM(shares) AS shares FROM transactions WHERE id = :userid GROUP BY name",
                          userid=session["user_id"])

        # If user owns stock
        if len(rows) != 0:

            # If user wants to sell less than amount owned
            if shares <= int(rows[0]["shares"]):
                # Insert new transaction into transactions table
                db.execute("INSERT INTO transactions (id, name, price, shares) VALUES (:userid, :name, :price, :shares)",
                           price=price, name=name, shares=-shares, userid=session["user_id"])
                # Update users table
                db.execute("UPDATE users SET cash = cash + :moneygained WHERE id = :userid",
                           moneygained=moneygained, userid=session["user_id"])

            elif shares > int(rows[0]["shares"]):
                return apology("You don't have enough of this stock")

        # If user does not own stock
        else:
            return apology("You don't own this stock")

        # Redirect user to homepage
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("sell.html")


@app.route("/passchange", methods=["GET", "POST"])
@login_required
def passchange():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password")

        # Ensure newpassword was submitted
        elif not request.form.get("newpassword"):
            return apology("must provide new password")

        # Ensure confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide confirmation")

        # Store user inputs from form into variables
        password = request.form.get("password")
        newpassword = request.form.get("newpassword")
        confirmation = request.form.get("confirmation")

        # Select the hashed password from users table for the logged-in user
        rows = db.execute("SELECT hash FROM users WHERE id = :userid",
                          userid=session["user_id"])

        # Check if inputted password matches user's password in users database
        if not check_password_hash(rows[0]["hash"], password):
            return apology("password incorrect")

        # Check if newpassword matches confirmation
        if newpassword != confirmation:
            return apology("password and confirmation do not match")

        else:
            # Hash the user's newpassword
            newpasshash = generate_password_hash(newpassword, method='pbkdf2:sha256', salt_length=8)

            # Update users table with newpassword
            db.execute("UPDATE users SET hash = :newpasshash WHERE id = :userid",
                       newpasshash=newpasshash, userid=session["user_id"])

        # Redirect user to homepage
        return redirect("/")

    else:
        return render_template("passchange.html")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

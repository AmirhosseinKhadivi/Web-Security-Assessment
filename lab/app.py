import sqlite3
from contextlib import closing

from flask import (
    Flask,
    make_response,
    redirect,
    render_template_string,
    request,
)
from markupsafe import escape

app = Flask(__name__)

PRODUCTS = [
    (1, "Notebook", 12),
    (2, "Desk Lamp", 35),
    (3, "Keyboard", 48),
]

PRODUCT_PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Product Lookup Lab</title>
</head>
<body>
    <h1>Product Lookup Lab</h1>

    <form method="get">
        <label for="product-id">Product ID</label>
        <input
            id="product-id"
            name="id"
            type="text"
            value="{{ product_id }}"
        >
        <button type="submit">Search</button>
    </form>

    {% if query_failed %}
        <p id="query-error">The product query could not be completed.</p>
    {% else %}
        <p>Results: <span id="result-count">{{ products | length }}</span></p>

        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Price</th>
                </tr>
            </thead>
            <tbody>
                {% for product in products %}
                    <tr data-product-id="{{ product[0] }}">
                        <td>{{ product[0] }}</td>
                        <td>{{ product[1] }}</td>
                        <td>{{ product[2] }}</td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>
    {% endif %}

    <p><a href="/">Back to the lab</a></p>
</body>
</html>
"""


def create_database():
    connection = sqlite3.connect(":memory:")

    connection.execute(
        """
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            price INTEGER NOT NULL
        )
        """
    )

    connection.executemany(
        "INSERT INTO products (id, name, price) VALUES (?, ?, ?)",
        PRODUCTS,
    )
    connection.commit()

    # All lookup queries are read-only.
    connection.execute("PRAGMA query_only = ON")

    return connection


def product_lookup(use_parameters):
    product_id = request.args.get("id", "1")
    products = []
    query_failed = False

    with closing(create_database()) as connection:
        try:
            if use_parameters:
                products = connection.execute(
                    "SELECT id, name, price FROM products WHERE id = ?",
                    (product_id,),
                ).fetchall()
            else:
                # Intentionally vulnerable for the local SQL injection lab.
                query = (
                    "SELECT id, name, price FROM products "
                    f"WHERE id = {product_id}"
                )
                products = connection.execute(query).fetchall()

        except sqlite3.Error:
            query_failed = True

    page = render_template_string(
        PRODUCT_PAGE,
        product_id=product_id,
        products=products,
        query_failed=query_failed,
    )

    return page, 400 if query_failed else 200


@app.route("/")
def home():
    return """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Local Security Lab</title>
    </head>
    <body>
        <h1>Local Security Lab</h1>

        <h2>XSS Lab</h2>
        <ul>
            <li><a href="/unsafe?name=Alice">Unsafe greeting</a></li>
            <li><a href="/safe?name=Alice">Safe greeting</a></li>
        </ul>

        <h2>SQL Injection Lab</h2>
        <ul>
            <li><a href="/sqli-unsafe?id=1">Unsafe product lookup</a></li>
            <li><a href="/sqli-safe?id=1">Parameterized product lookup</a></li>
        </ul>
        <h2>Cookie Security Lab</h2>
        <ul>
            <li><a href="/cookie-unsafe">Unsafe cookie</a></li>
            <li><a href="/cookie-safe">Safe cookie</a></li>
        </ul>
        <h2>Error Disclosure Lab</h2>
        <ul>
            <li><a href="/error-unsafe">Verbose error response</a></li>
            <li><a href="/error-safe">Generic error response</a></li>
        </ul>
        <h2>Open Redirect Lab</h2>
        <ul>
            <li>
                <a href="/redirect-unsafe?next=https://example.com">
                    Unsafe redirect
                </a>
            </li>
            <li>
                <a href="/redirect-safe?next=https://example.com">
                    Safe redirect
                </a>
            </li>
        </ul>
        <h2>CORS Lab</h2>
        <ul>
            <li><a href="/cors-unsafe">Unsafe CORS</a></li>
            <li><a href="/cors-safe">Safe CORS</a></li>
        </ul>
    </body>
    </html>
    """


@app.route("/unsafe")
def unsafe():
    name = request.args.get("name", "Guest")
    return f"<h1>Hello, {name}</h1>"


@app.route("/safe")
def safe():
    name = request.args.get("name", "Guest")
    return f"<h1>Hello, {escape(name)}</h1>"


@app.route("/sqli-unsafe")
def sqli_unsafe():
    return product_lookup(use_parameters=False)


@app.route("/sqli-safe")
def sqli_safe():
    return product_lookup(use_parameters=True)


@app.route("/cookie-unsafe")
def cookie_unsafe():
    response = make_response("<h1>Unsafe Cookie Lab</h1>")
    response.set_cookie(
        "unsafe_session",
        "demo-value",
    )
    return response


@app.route("/cookie-safe")
def cookie_safe():
    response = make_response("<h1>Safe Cookie Lab</h1>")
    response.set_cookie(
        "safe_session",
        "demo-value",
        secure=True,
        httponly=True,
        samesite="Lax",
    )
    return response


@app.route("/error-unsafe")
def error_unsafe():
    body = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Verbose Error Lab</title>
    </head>
    <body>
        <h1>Internal Server Error</h1>
        <pre>
Traceback (most recent call last):
  File "/srv/app/views.py", line 42, in demo
    result = service.load_record()
  File "/srv/app/service.py", line 18, in load_record
    raise RuntimeError("Demo database failure")
RuntimeError: Demo database failure
        </pre>
    </body>
    </html>
    """

    return body, 500


@app.route("/error-safe")
def error_safe():
    body = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Generic Error Lab</title>
    </head>
    <body>
        <h1>Something went wrong</h1>
        <p>Please try again later.</p>
    </body>
    </html>
    """

    return body, 500


@app.route("/redirect-unsafe")
def redirect_unsafe():
    next_url = request.args.get("next", "/")
    return redirect(next_url)


@app.route("/redirect-safe")
def redirect_safe():
    next_url = request.args.get("next", "/")

    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = "/"

    return redirect(next_url)


@app.route("/cors-unsafe")
def cors_unsafe():
    origin = request.headers.get("Origin", "")

    response = make_response(
        "<h1>Unsafe CORS Lab</h1>"
    )

    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"

    return response


@app.route("/cors-safe")
def cors_safe():
    origin = request.headers.get("Origin", "")

    response = make_response(
        "<h1>Safe CORS Lab</h1>"
    )

    allowed_origin = "https://trusted.example"

    if origin == allowed_origin:
        response.headers["Access-Control-Allow-Origin"] = allowed_origin
        response.headers["Access-Control-Allow-Credentials"] = "true"

    return response


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5001,
        debug=False,
        use_reloader=False,
    )

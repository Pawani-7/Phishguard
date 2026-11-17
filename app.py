"""PhishGuard web page.

Paste a link, see its risk level and the reasons, and keep a history.
Links are analysed as TEXT only. They are never opened, and they are
never shown as clickable links on the page.

Run with:  python app.py
Then open: http://127.0.0.1:5000
"""

import sqlite3
from datetime import datetime
from pathlib import Path

from flask import redirect, url_for
from flask import Flask, render_template_string, request

from scoring import analyse

MAX_LINK_LENGTH = 2000
HISTORY_LIMIT = 20

app = Flask(__name__)
app.config["DB_FILE"] = str(Path(__file__).with_name("phishguard_history.db"))

PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishGuard | URL Security Analyzer</title>

    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: Arial, sans-serif;
            background: #0b1220;
            color: #e2e8f0;
            min-height: 100vh;
            padding: 30px 16px;
        }

        .container {
            max-width: 1000px;
            margin: auto;
        }

        header {
            display: flex;
            align-items: center;
            gap: 14px;
            margin-bottom: 35px;
        }

        .logo {
            background: #12352f;
            color: #42e6a4;
            padding: 13px;
            border-radius: 12px;
            font-size: 25px;
        }

        h1 {
            color: #ffffff;
            font-size: 27px;
        }

        .subtitle {
            color: #94a3b8;
            margin-top: 5px;
            font-size: 14px;
        }

        .panel {
            background: #111c2e;
            border: 1px solid #263449;
            border-radius: 14px;
            padding: 25px;
            margin-bottom: 22px;
        }

        h2 {
            color: #ffffff;
            font-size: 19px;
            margin-bottom: 18px;
        }

        input {
            width: 100%;
            padding: 15px;
            background: #172337;
            border: 1px solid #334155;
            border-radius: 8px;
            color: white;
            font-size: 15px;
            outline: none;
        }

        input:focus {
            border-color: #42e6a4;
        }

        button {
            width: 100%;
            margin-top: 15px;
            padding: 14px;
            background: #16a878;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 15px;
            font-weight: bold;
            cursor: pointer;
        }

        button:hover {
            background: #128b64;
        }

        .result {
            border-left: 4px solid #42e6a4;
        }

        .risk {
            font-size: 25px;
            font-weight: bold;
            margin: 12px 0;
        }

        .low {
            color: #42e6a4;
        }

        .medium {
            color: #fbbf24;
        }

        .high {
            color: #fb7185;
        }

        .score {
            color: #cbd5e1;
            margin-bottom: 15px;
        }

        .url {
            color: #94a3b8;
            overflow-wrap: anywhere;
            margin-bottom: 15px;
            font-size: 14px;
        }

        ul {
            padding-left: 22px;
            color: #cbd5e1;
        }

        li {
            margin: 8px 0;
        }

        .notice {
            color: #94a3b8;
            font-size: 13px;
            line-height: 1.6;
            margin-top: 18px;
        }

        .table-wrap {
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }

        th, td {
            text-align: left;
            padding: 13px;
            border-bottom: 1px solid #263449;
        }

        th {
            color: #94a3b8;
        }

        td {
            color: #e2e8f0;
            overflow-wrap: anywhere;
        }

        .empty {
            color: #94a3b8;
            padding: 12px 0;
        }

        footer {
            text-align: center;
            color: #64748b;
            font-size: 13px;
            margin-top: 30px;
        }
    </style>
</head>

<body>
<div class="container">

    <header>
        <div class="logo">🛡</div>
        <div>
            <h1>PhishGuard</h1>
            <p class="subtitle">URL Threat Analysis System</p>
        </div>
    </header>

    <section class="panel">
        <h2>Analyze a URL</h2>

        <form method="POST">
            <input
                type="text"
                name="url"
                placeholder="Enter URL to analyze..."
                maxlength="2000"
                required
            >

            <button type="submit">Analyze URL</button>
        </form>
        {% if error %}
        <p style="color: #fb7185; margin-top: 12px;">
          {{ error }}
        </p>
        {% endif %}

        <p class="notice">
            Enter a URL to evaluate its suspicious characteristics.
            PhishGuard analyzes URL text only and never opens the submitted link.
        </p>
    </section>

    {% if result %}
    <section class="panel result">
        <h2>Analysis Result</h2>

        <p class="url">
            URL: {{ result.url }}
        </p>

        <div class="risk {{ result.level|lower }}">
            {{ result.level|upper }} RISK
        </div>

        <p class="score">
            Risk Score: <strong>{{ result.score }}</strong>
        </p>

        <h2>Detection Reasons</h2>

        {% if result.reasons %}
            <ul>
                {% for reason in result.reasons %}
                    <li>{{ reason }}</li>
                {% endfor %}
            </ul>
        {% else %}
            <p class="empty">No suspicious indicators detected.</p>
        {% endif %}
    </section>
    {% endif %}

    <section class="panel">
        <h2>Recent Analysis History</h2>
        {% if history %}
        <form method="POST" action="/clear-history"
              onsubmit="return confirm('Are you sure you want to clear all history?');">
            <button type="submit"
                    style="background:#be123c; margin-bottom:18px;">
                Clear History
            </button>
        </form>
        {% endif %}


        {% if history %}
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Score</th>
                        <th>Risk Level</th>
                        <th>Date</th>
                    </tr>
                </thead>

                <tbody>
                    {% for item in history %}
                    <tr>
                        <td>{{ item.url }}</td>
                        <td>{{ item.score }}</td>
                        <td>{{ item.level }}</td>
                        <td>{{ item.timestamp }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
            <p class="empty">No analysis history available yet.</p>
        {% endif %}
    </section>

    <footer>
        PhishGuard | Educational Cybersecurity Project
    </footer>

</div>
</body>
</html>
"""



def get_db():
    conn = sqlite3.connect(app.config["DB_FILE"])
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the history table if it does not exist yet."""
    conn = get_db()
    try:
        with conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS history (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       url TEXT NOT NULL,
                       score INTEGER NOT NULL,
                       level TEXT NOT NULL,
                       reasons TEXT NOT NULL,
                       checked_at TEXT NOT NULL)"""
            )
    finally:
        conn.close()

def save_result(result):
    """Store one checked link in the history table."""
    conn = get_db()
    try:
        with conn:
            conn.execute(
                "INSERT INTO history (url, score, level, reasons, checked_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    result["url"],
                    result["score"],
                    result["level"],
                    " | ".join(result["reasons"]),
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )
    finally:
        conn.close()


def recent_history(limit=HISTORY_LIMIT):
    """Return the most recent checks, newest first."""
    conn = get_db()
    try:
        return conn.execute(
            "SELECT url, score, level, reasons, checked_at "
            "FROM history ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    finally:
        conn.close()



def clear_history():
    """Delete all saved analysis history."""
    conn = get_db()
    try:
        with conn:
            conn.execute("DELETE FROM history")
    finally:
        conn.close()



@app.route("/clear-history", methods=["POST"])
def clear_history_route():
    clear_history()
    return redirect(url_for("index"))




@app.route("/", methods=["GET", "POST"])
def index():
    init_db()
    result = None
    url = ""
    error = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()

        if not url:
            error = "Please enter a URL."

        elif len(url) > MAX_LINK_LENGTH:
            error = f"URL must not exceed {MAX_LINK_LENGTH} characters."

        elif not url.startswith(("http://", "https://")):
            error = "Please enter a URL starting with http:// or https://."

        else:
            result = analyse(url)
            save_result(result)

    return render_template_string(
        PAGE,
        result=result,
        url=url,
        history=recent_history(),
        error=error
    )



if __name__ == "__main__":
    # Local use only: the page is served on your own computer (127.0.0.1)
    app.run(host="127.0.0.1", port=5000, debug=False)
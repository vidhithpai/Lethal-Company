from flask import Flask, request
import subprocess
import db
import utils

app = Flask(__name__)


@app.route("/search")
def search():
    # VULNERABILITY: SQL injection — user input directly in query
    query = request.args.get("q", "")
    results = db.search_users(query)
    return str(results)


@app.route("/run")
def run_command():
    # VULNERABILITY: Command injection
    cmd = request.args.get("cmd", "")
    output = subprocess.run(cmd, shell=True, capture_output=True)
    return output.stdout.decode()


@app.route("/file")
def read_file():
    # VULNERABILITY: Path traversal
    filename = request.args.get("name", "")
    return utils.read_file(filename)


@app.route("/eval_expr")
def evaluate():
    # VULNERABILITY: Code injection via eval
    expr = request.args.get("expr", "")
    result = eval(expr)
    return str(result)


@app.route("/safe_search")
def safe_search():
    # SAFE: parameterized query
    query = request.args.get("q", "")
    results = db.safe_search_users(query)
    return str(results)


@app.route("/safe_run")
def safe_run():
    # SAFE: no shell=True, validated command
    cmd = request.args.get("cmd", "")
    clean = utils.sanitize_input(cmd)
    output = subprocess.run(["echo", clean], capture_output=True)
    return output.stdout.decode()


if __name__ == "__main__":
    app.run(debug=True)

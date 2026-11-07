from flask import Flask, request

app = Flask(__name__)


@app.route("/lookup")
def lookup_page():
    term = request.args.get("term", "")
    return "<p>You searched for: %s</p>" % term

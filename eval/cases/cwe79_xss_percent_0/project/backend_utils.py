from flask import Flask, request

app = Flask(__name__)


@app.route("/filter")
def filter_page():
    tag = request.args.get("tag", "")
    return "<p>Showing items tagged: %s</p>" % tag

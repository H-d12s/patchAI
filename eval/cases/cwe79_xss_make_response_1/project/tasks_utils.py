from flask import Flask, make_response, request

app = Flask(__name__)


@app.route("/catalog")
def missing_catalog():
    item = request.args.get("item", "unknown")
    return make_response("<h2>Nothing found for " + item + "</h2>", 404)

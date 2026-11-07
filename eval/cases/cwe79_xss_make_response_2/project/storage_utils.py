from flask import Flask, make_response, request

app = Flask(__name__)


@app.route("/wiki")
def missing_wiki():
    article = request.args.get("article", "unknown")
    return make_response("<h2>Nothing found for " + article + "</h2>", 404)

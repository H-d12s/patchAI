from flask import Flask, make_response, request

app = Flask(__name__)


@app.route("/user")
def missing_user():
    handle = request.args.get("handle", "unknown")
    return make_response("<h2>Nothing found for " + handle + "</h2>", 404)

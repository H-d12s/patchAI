"""Run the (intentionally vulnerable) demo shop locally: python run.py"""

from shop import create_app

if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)

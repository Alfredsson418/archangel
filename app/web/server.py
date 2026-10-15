import os

from webapp import create_app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.getenv("WEB_HOST", "127.0.0.1"),
        port=int(os.getenv("WEB_PORT", "8081")),
        debug=False,
    )

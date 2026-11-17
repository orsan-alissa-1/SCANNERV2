from app import app
import os

if __name__ == "__main__":
    # Dev mode only – not for production
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Starting Flask app on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)

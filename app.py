from flask import Flask, request, jsonify

app = Flask(__name__)

USERS = {
    "admin": "admin123",
    "muneeb": "password123",
    "guest": "guest123"
}

def vulnerable_search(username):
    ldap_filter = f"(uid={username})"
    if "*" in username or ")(uid=" in username:
        return list(USERS.keys())
    if username in USERS:
        return [username]
    return []

def safe_search(username):
    escaped = username.replace("*", "").replace("(", "").replace(")", "").replace("\\", "")
    if escaped in USERS:
        return [escaped]
    return []

@app.route("/")
def home():
    return "LDAPProbe Lab is Running. Use /login and /safe-login"

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    result = vulnerable_search(username)
    if result:
        return jsonify({"status": "Login Success", "users": result, "filter": f"(uid={username})"})
    return jsonify({"status": "Login Failed"})

@app.route("/safe-login", methods=["POST"])
def safe_login():
    username = request.form.get("username", "")
    result = safe_search(username)
    if result:
        return jsonify({"status": "Login Success", "users": result})
    return jsonify({"status": "Login Failed"})

@app.route("/search", methods=["GET"])
def search():
    q = request.args.get("q", "")
    if "*" in q:
        return jsonify({"status": "Found All", "result": list(USERS.keys())})
    if q in USERS:
        return jsonify({"status": "Found", "user": q})
    return jsonify({"status": "Not Found"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

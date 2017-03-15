from flask import Flask, jsonify, request, render_template, make_response
from redis import StrictRedis
import os, hashlib, uuid, logging

get_hash = lambda: hashlib.md5(uuid.uuid4().bytes).hexdigest()[:12]

app = Flask(__name__)

db = StrictRedis.from_url(os.environ['REDIS_URL'], db=2, decode_responses=True)

@app.before_first_request
def setup_logging():
    app.logger.addHandler(logging.StreamHandler())
    app.logger.setLevel(logging.INFO)


@app.route('/api/v1/create', methods=['POST'])
def api_v1_create():
    if 'ciphertext' not in request.form:
        return make_response(jsonify(error='Bad Request'), 400)

    ciphertext = request.form['ciphertext']

    if (not isinstance(ciphertext, str)) or (len(ciphertext) > 5100) or (len(ciphertext) == 0):
        return make_response(jsonify(error='Bad Request'), 400)

    key = get_hash()
    db.set(key, ciphertext)

    if ('token' in request.form) and ('encryptedToken' in request.form):
        db.set(key + "_encryptedToken", request.form['encryptedToken'])
        db.set(key + "_" + request.form['token'], True)

    return make_response(jsonify(error=None, key=key), 200)


@app.route('/api/v1/destruct', methods=['POST'])
def api_v1_destruct():
    if ('key' not in request.form) or ('token' not in request.form):
        return make_response(jsonify(error='Bad Request'), 400)

    key = request.form['key']
    token = request.form['token']

    if (not len(key) == 12) or (not len(token) == 64):
        return make_response(jsonify(error='Bad Request'), 400)

    if db.exists(key + "_" + token):
        db.delete(key, key + "_encryptedToken", key + "_" + token)
        return make_response(jsonify(error=None, success="true"), 200)
    else:
        return make_response(jsonify(error=None, success="false"), 200)


@app.route("/")
def index():
    googleAnalyticsId = ""
    if 'GOOGLE_ANALYTICS_ID' in os.environ:
        googleAnalyticsId = os.environ['GOOGLE_ANALYTICS_ID']

    return render_template("index.html", analyticsId=googleAnalyticsId)


@app.route("/<key>")
def paste(key):
    if not db.exists(key):
        return render_template("404.html", key=key), 404

    ciphertext = db.get(key)

    encryptedToken = ""
    if db.exists(key + "_encryptedToken"):
        encryptedToken = db.get(key + "_encryptedToken")

    googleAnalyticsId = ""
    if 'GOOGLE_ANALYTICS_ID' in os.environ:
        googleAnalyticsId = os.environ['GOOGLE_ANALYTICS_ID']

    return render_template("paste.html", ciphertext=str(ciphertext),
        encryptedToken=str(encryptedToken), key=key, analyticsId=googleAnalyticsId)


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)

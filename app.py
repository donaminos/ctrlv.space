from flask import Flask, jsonify, request, render_template, make_response
import os, hashlib, uuid, logging
from datetime import timedelta, datetime
import boto3

client = boto3.client('s3')

BUCKET = os.environ.get('S3_BUCKET', "")
if BUCKET == "":
    raise "S3_BUCKET environment variable is unset."

get_hash = lambda: hashlib.md5(uuid.uuid4().bytes).hexdigest()[:12]

app = Flask(__name__)

@app.before_first_request
def setup_logging():
    app.logger.addHandler(logging.StreamHandler())
    app.logger.setLevel(logging.INFO)


def destructOptionToExpires(destructOption):
    expires = datetime.now()
    if destructOption == "1h":
        expires += timedelta(hours=1)
    elif destructOption == "1d":
        expires += timedelta(days=1)
    elif destructOption == "1w":
        expires += timedelta(weeks=1)

    return expires

@app.route('/api/v1/create', methods=['POST'])
def api_v1_create():
    if 'ciphertext' not in request.form:
        return make_response(jsonify(error='Bad Request'), 400)

    maxLength = int(os.environ.get('MAX_LENGTH', 5000))

    ciphertext = request.form['ciphertext']

    if (not isinstance(ciphertext, str)) or (len(ciphertext) > maxLength) or (len(ciphertext) == 0):
        return make_response(jsonify(error='Bad Request'), 400)

    key = get_hash()

    s3_object = {
        "Key": key,
        "Body": ciphertext,
        "Bucket": BUCKET,
        "Metadata": {
            'encryptedtoken': request.form['encryptedToken'] if ('token' in request.form) and ('encryptedToken' in request.form) else "",
            'token': request.form['token'] if 'token' in request.form else ""
        }
    }

    if 'destructOption' in request.form:
        s3_object["Expires"] = destructOptionToExpires(request.form['destructOption'])

    client.put_object(**s3_object)

    return make_response(jsonify(error=None, key=key), 200)


@app.route('/api/v1/destruct', methods=['POST'])
def api_v1_destruct():
    if ('key' not in request.form) or ('token' not in request.form):
        return make_response(jsonify(error='Bad Request'), 400)

    key = request.form['key']
    token = request.form['token']

    if (not len(key) == 12) or (not len(token) == 64):
        return make_response(jsonify(error='Bad Request'), 400)

    s3_object = None
    try:
        s3_object = client.get_object(Bucket=BUCKET, Key=key)
    except ClientError as ex:
        if ex.response['Error']['Code'] == 'NoSuchKey':
            logger.info('No object found - returning empty')
            return render_template("404.html", key=key), 404
        return

    if s3_object["Metadata"].get("token") == request.form['token']:
        client.delete_object(
            Bucket=BUCKET,
            Key=key,
        )
        return make_response(jsonify(error=None, success="true"), 200)
    else:
        return make_response(jsonify(error=None, success="false"), 200)


@app.route('/health')
def health_check():
    return make_response("", 200)


@app.route("/")
def index():
    selfDestructMandatory = os.environ.get('SELF_DESTRUCT_MANDATORY', "false")
    maxLength = int(os.environ.get('MAX_LENGTH', 5000))
    googleAnalyticsId = os.environ.get('GOOGLE_ANALYTICS_ID', "")

    return render_template("index.html", selfDestructMandatory=selfDestructMandatory,
        maxLength=maxLength, analyticsId=googleAnalyticsId)


@app.route("/<key>")
def paste(key):

    s3_object = None
    try:
        s3_object = client.get_object(Bucket=BUCKET, Key=key)
    except client.exceptions.NoSuchKey as ex:
        return render_template("404.html", key=key), 404

    ciphertext = s3_object["Body"].read()

    encryptedToken = s3_object["Metadata"]["encryptedtoken"] if 'encryptedtoken' in s3_object["Metadata"] else ""

    googleAnalyticsId = os.environ.get('GOOGLE_ANALYTICS_ID', "")

    return render_template("paste.html", ciphertext=ciphertext.decode('UTF-8'),
        encryptedToken=encryptedToken, key=key, analyticsId=googleAnalyticsId)

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000)

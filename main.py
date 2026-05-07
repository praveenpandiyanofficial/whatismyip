from flask import Flask, request, jsonify, render_template_string
from datetime import datetime
import os
import time
import hashlib
import ipaddress

app = Flask(__name__)

"""
|--------------------------------------------------------------------------
| RATE LIMIT SETTINGS
|--------------------------------------------------------------------------
"""

RATE_LIMIT = 60
RATE_WINDOW = 60

rate_store = {}

"""
|--------------------------------------------------------------------------
| GET REAL CLIENT IPS
|--------------------------------------------------------------------------
"""


def get_client_ips():

    ipv4 = None
    ipv6 = None

    possible_ips = []

    headers = [
        request.headers.get('CF-Connecting-IP'),
        request.headers.get('X-Real-IP'),
        request.remote_addr
    ]

    x_forwarded_for = request.headers.get('X-Forwarded-For')

    if x_forwarded_for:
        for ip in x_forwarded_for.split(','):
            possible_ips.append(ip.strip())

    possible_ips.extend(headers)

    for ip in possible_ips:

        if not ip:
            continue

        try:

            parsed_ip = ipaddress.ip_address(ip)

            if (
                parsed_ip.is_private or
                parsed_ip.is_reserved or
                parsed_ip.is_loopback
            ):
                continue

            if parsed_ip.version == 4 and not ipv4:
                ipv4 = ip

            if parsed_ip.version == 6 and not ipv6:
                ipv6 = ip

        except ValueError:
            continue

    return {
        "ipv4": ipv4,
        "ipv6": ipv6
    }


"""
|--------------------------------------------------------------------------
| RATE LIMIT FUNCTION
|--------------------------------------------------------------------------
"""


def is_rate_limited(ip):

    current_time = int(time.time())

    if ip not in rate_store:

        rate_store[ip] = {
            "count": 1,
            "time": current_time
        }

        return False

    data = rate_store[ip]

    if (current_time - data["time"]) > RATE_WINDOW:

        rate_store[ip] = {
            "count": 1,
            "time": current_time
        }

        return False

    data["count"] += 1

    if data["count"] > RATE_LIMIT:
        return True

    return False


"""
|--------------------------------------------------------------------------
| MAIN ROUTE
|--------------------------------------------------------------------------
"""


@app.route("/")
def index():

    ips = get_client_ips()

    client_ip = ips["ipv4"] or ips["ipv6"] or "unknown"

    if is_rate_limited(client_ip):

        return jsonify({
            "success": False,
            "message": "Too many requests"
        }), 429

    user_agent = request.headers.get(
        'User-Agent',
        'Unknown'
    )[:300]

    response = {
        "success": True,
        "ipv4": ips["ipv4"],
        "ipv6": ips["ipv6"],
        "ip_version": "IPv6" if ips["ipv6"] else "IPv4",
        "user_agent": user_agent,
        "request_time": datetime.utcnow().isoformat() + "Z",
        "server": {
            "software": "Flask",
            "protocol": request.environ.get("SERVER_PROTOCOL")
        }
    }

    """
    |--------------------------------------------------------------------------
    | JSON API MODE
    |--------------------------------------------------------------------------
    """

    if (
        request.args.get("api") == "1"
        or
        request.args.get("format") == "json"
    ):

        return jsonify(response)

    """
    |--------------------------------------------------------------------------
    | HTML PAGE
    |--------------------------------------------------------------------------
    """

    html = """
<!DOCTYPE html>
<html lang="en">
<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>What Is My IP</title>

<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    padding:20px;
    font-family:Arial,sans-serif;
    background:#0f172a;
    color:white;
    display:flex;
    justify-content:center;
    align-items:center;
    min-height:100vh;
}

.container{
    width:100%;
    max-width:750px;
    background:#1e293b;
    border-radius:20px;
    padding:40px;
    box-shadow:0 0 30px rgba(0,0,0,0.4);
}

h1{
    text-align:center;
    color:#38bdf8;
    margin-bottom:35px;
}

.card{
    background:#0f172a;
    padding:20px;
    border-radius:14px;
    margin-bottom:20px;
    border-left:5px solid #38bdf8;
}

.label{
    color:#94a3b8;
    margin-bottom:10px;
    font-size:14px;
}

.value{
    font-size:22px;
    font-weight:bold;
    word-break:break-word;
}

.not-found{
    color:#f87171;
}

.btn{
    display:block;
    text-align:center;
    text-decoration:none;
    background:#38bdf8;
    color:#000;
    padding:15px;
    border-radius:12px;
    font-weight:bold;
    margin-top:25px;
}

.json-preview{
    margin-top:30px;
    background:#020617;
    padding:20px;
    border-radius:12px;
    overflow:auto;
}

pre{
    margin:0;
    color:#4ade80;
    font-size:14px;
    white-space:pre-wrap;
    word-break:break-word;
}

.footer{
    margin-top:25px;
    text-align:center;
    color:#94a3b8;
    font-size:13px;
}

</style>

</head>
<body>

<div class="container">

<h1>🌍 What Is My IP</h1>

<div class="card">

<div class="label">IPv4 Address</div>

<div class="value">
{{ ipv4 if ipv4 else '<span class="not-found">Not Detected</span>'|safe }}
</div>

</div>

<div class="card">

<div class="label">IPv6 Address</div>

<div class="value">
{{ ipv6 if ipv6 else '<span class="not-found">Not Detected</span>'|safe }}
</div>

</div>

<a class="btn"
   href="?api=1"
   target="_blank">

Open Secure JSON API

</a>

<div class="json-preview">

<pre>{{ json_data }}</pre>

</div>

<div class="footer">
Secure IPv4 / IPv6 Detection API
</div>

</div>

</body>
</html>
"""

    return render_template_string(
        html,
        ipv4=ips["ipv4"],
        ipv6=ips["ipv6"],
        json_data=response
    )


"""
|--------------------------------------------------------------------------
| SECURITY HEADERS
|--------------------------------------------------------------------------
"""


@app.after_request
def secure_headers(response):

    response.headers['X-Frame-Options'] = 'DENY'

    response.headers['X-Content-Type-Options'] = 'nosniff'

    response.headers['Referrer-Policy'] = 'no-referrer'

    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline';"
    )

    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=()'
    )

    return response


"""
|--------------------------------------------------------------------------
| START SERVER
|--------------------------------------------------------------------------
"""

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )

const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const net = require('net');

const app = express();

/*
|--------------------------------------------------------------------------
| TRUST PROXY
|--------------------------------------------------------------------------
*/

app.set('trust proxy', true);

/*
|--------------------------------------------------------------------------
| SECURITY HEADERS
|--------------------------------------------------------------------------
*/

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"]
            }
        }
    })
);

/*
|--------------------------------------------------------------------------
| RATE LIMIT
|--------------------------------------------------------------------------
*/

const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'Too many requests'
    }
});

app.use(limiter);

/*
|--------------------------------------------------------------------------
| GET CLIENT IPS
|--------------------------------------------------------------------------
*/

function getClientIps(req) {

    let ipv4 = null;
    let ipv6 = null;

    const possibleIps = [];

    /*
    |--------------------------------------------------------------------------
    | Cloudflare
    |--------------------------------------------------------------------------
    */

    if (req.headers['cf-connecting-ip']) {
        possibleIps.push(req.headers['cf-connecting-ip']);
    }

    /*
    |--------------------------------------------------------------------------
    | Nginx Real IP
    |--------------------------------------------------------------------------
    */

    if (req.headers['x-real-ip']) {
        possibleIps.push(req.headers['x-real-ip']);
    }

    /*
    |--------------------------------------------------------------------------
    | X-Forwarded-For
    |--------------------------------------------------------------------------
    */

    if (req.headers['x-forwarded-for']) {

        const forwardedIps =
            req.headers['x-forwarded-for']
                .split(',');

        forwardedIps.forEach(ip => {
            possibleIps.push(ip.trim());
        });
    }

    /*
    |--------------------------------------------------------------------------
    | Remote Address
    |--------------------------------------------------------------------------
    */

    if (req.socket.remoteAddress) {
        possibleIps.push(req.socket.remoteAddress);
    }

    /*
    |--------------------------------------------------------------------------
    | Validate IPs
    |--------------------------------------------------------------------------
    */

    possibleIps.forEach(ip => {

        if (!ip) {
            return;
        }

        /*
        |--------------------------------------------------------------------------
        | Remove IPv6 mapped IPv4
        |--------------------------------------------------------------------------
        */

        ip = ip.replace('::ffff:', '');

        if (!net.isIP(ip)) {
            return;
        }

        /*
        |--------------------------------------------------------------------------
        | Detect IPv4
        |--------------------------------------------------------------------------
        */

        if (net.isIPv4(ip) && !ipv4) {
            ipv4 = ip;
        }

        /*
        |--------------------------------------------------------------------------
        | Detect IPv6
        |--------------------------------------------------------------------------
        */

        if (net.isIPv6(ip) && !ipv6) {
            ipv6 = ip;
        }
    });

    return {
        ipv4,
        ipv6
    };
}

/*
|--------------------------------------------------------------------------
| MAIN ROUTE
|--------------------------------------------------------------------------
*/

app.get('/', (req, res) => {

    const ips = getClientIps(req);

    /*
    |--------------------------------------------------------------------------
    | SAFE USER AGENT
    |--------------------------------------------------------------------------
    */

    const userAgent =
        (req.headers['user-agent'] || 'Unknown')
            .replace(/[<>]/g, '')
            .substring(0, 300);

    /*
    |--------------------------------------------------------------------------
    | API RESPONSE
    |--------------------------------------------------------------------------
    */

    const response = {

        success: true,

        ipv4: ips.ipv4,

        ipv6: ips.ipv6,

        ip_version: ips.ipv6
            ? 'IPv6'
            : 'IPv4',

        user_agent: userAgent,

        request_time: new Date().toISOString(),

        server: {
            software: 'Node.js Express',
            protocol: `HTTP/${req.httpVersion}`
        }
    };

    /*
    |--------------------------------------------------------------------------
    | JSON API MODE
    |--------------------------------------------------------------------------
    */

    if (
        req.query.api === '1'
        ||
        req.query.format === 'json'
    ) {

        return res.json(response);
    }

    /*
    |--------------------------------------------------------------------------
    | HTML RESPONSE
    |--------------------------------------------------------------------------
    */

    res.send(`
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
${ips.ipv4 || '<span class="not-found">Not Detected</span>'}
</div>

</div>

<div class="card">

<div class="label">IPv6 Address</div>

<div class="value">
${ips.ipv6 || '<span class="not-found">Not Detected</span>'}
</div>

</div>

<a class="btn"
   href="?api=1"
   target="_blank">

Open Secure JSON API

</a>

<div class="json-preview">

<pre>${JSON.stringify(response, null, 4)}</pre>

</div>

<div class="footer">
Secure IPv4 / IPv6 Detection API
</div>

</div>

</body>
</html>
`);
});

/*
|--------------------------------------------------------------------------
| START SERVER
|--------------------------------------------------------------------------
*/

const PORT = 5000;

app.listen(PORT, '0.0.0.0', () => {

    console.log(
        `Server running on http://0.0.0.0:${PORT}`
    );
});

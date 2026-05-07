<?php

/*
|--------------------------------------------------------------------------
| SECURITY HEADERS
|--------------------------------------------------------------------------
*/

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline';");
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

/*
|--------------------------------------------------------------------------
| RATE LIMIT DIRECTORY
|--------------------------------------------------------------------------
*/

$rateLimitDir = __DIR__ . '/rate_limit';

if (!is_dir($rateLimitDir)) {
    mkdir($rateLimitDir, 0755, true);
}

/*
|--------------------------------------------------------------------------
| GET REAL CLIENT IP
|--------------------------------------------------------------------------
*/

function getClientIps() {

    $ipv4 = null;
    $ipv6 = null;

    /*
    |--------------------------------------------------------------------------
    | Trusted Headers
    |--------------------------------------------------------------------------
    */

    $headers = [

        $_SERVER['HTTP_CF_CONNECTING_IP'] ?? null,
        $_SERVER['HTTP_X_REAL_IP'] ?? null,
        $_SERVER['REMOTE_ADDR'] ?? null

    ];

    /*
    |--------------------------------------------------------------------------
    | X-Forwarded-For
    |--------------------------------------------------------------------------
    */

    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {

        $forwardedIps = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);

        foreach ($forwardedIps as $forwardedIp) {
            $headers[] = trim($forwardedIp);
        }
    }

    /*
    |--------------------------------------------------------------------------
    | Validate IPs
    |--------------------------------------------------------------------------
    */

    foreach ($headers as $ip) {

        if (!$ip) {
            continue;
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            continue;
        }

        /*
        |--------------------------------------------------------------------------
        | Skip Private/Reserved IPs
        |--------------------------------------------------------------------------
        */

        if (
            !filter_var(
                $ip,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
            )
        ) {
            continue;
        }

        /*
        |--------------------------------------------------------------------------
        | Detect IPv4
        |--------------------------------------------------------------------------
        */

        if (
            filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
            && !$ipv4
        ) {
            $ipv4 = $ip;
        }

        /*
        |--------------------------------------------------------------------------
        | Detect IPv6
        |--------------------------------------------------------------------------
        */

        if (
            filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
            && !$ipv6
        ) {
            $ipv6 = $ip;
        }
    }

    return [
        'ipv4' => $ipv4,
        'ipv6' => $ipv6
    ];
}

/*
|--------------------------------------------------------------------------
| FETCH IPS
|--------------------------------------------------------------------------
*/

$ips = getClientIps();

$clientIp = $ips['ipv4'] ?? $ips['ipv6'] ?? 'unknown';

/*
|--------------------------------------------------------------------------
| BASIC RATE LIMIT
|--------------------------------------------------------------------------
| 60 Requests Per Minute
|--------------------------------------------------------------------------
*/

$rateFile = $rateLimitDir . '/' . md5($clientIp) . '.json';

$currentTime = time();

$limit = 60;

$window = 60;

$data = [
    'count' => 0,
    'time' => $currentTime
];

if (file_exists($rateFile)) {

    $stored = json_decode(file_get_contents($rateFile), true);

    if (
        $stored &&
        isset($stored['count']) &&
        isset($stored['time'])
    ) {

        if (($currentTime - $stored['time']) < $window) {

            $data = $stored;

        } else {

            $data = [
                'count' => 0,
                'time' => $currentTime
            ];
        }
    }
}

$data['count']++;

file_put_contents($rateFile, json_encode($data));

if ($data['count'] > $limit) {

    http_response_code(429);

    header('Content-Type: application/json');

    echo json_encode([
        'success' => false,
        'message' => 'Too many requests'
    ], JSON_PRETTY_PRINT);

    exit;
}

/*
|--------------------------------------------------------------------------
| SAFE USER AGENT
|--------------------------------------------------------------------------
*/

$userAgent = substr(
    strip_tags($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'),
    0,
    300
);

/*
|--------------------------------------------------------------------------
| API RESPONSE
|--------------------------------------------------------------------------
*/

$response = [

    'success' => true,

    'ipv4' => $ips['ipv4'],

    'ipv6' => $ips['ipv6'],

    'ip_version' => $ips['ipv6']
        ? 'IPv6'
        : 'IPv4',

    'user_agent' => $userAgent,

    'request_time' => gmdate('c'),

    'server' => [
        'software' => $_SERVER['SERVER_SOFTWARE'] ?? null,
        'protocol' => $_SERVER['SERVER_PROTOCOL'] ?? null
    ]
];

/*
|--------------------------------------------------------------------------
| JSON API MODE
|--------------------------------------------------------------------------
| Examples:
| ?api=1
| ?format=json
|--------------------------------------------------------------------------
*/

if (
    (isset($_GET['api']) && $_GET['api'] == '1')
    ||
    (isset($_GET['format']) && $_GET['format'] === 'json')
) {

    header('Content-Type: application/json; charset=UTF-8');

    echo json_encode(
        $response,
        JSON_PRETTY_PRINT |
        JSON_UNESCAPED_SLASHES |
        JSON_UNESCAPED_UNICODE
    );

    exit;
}

?>

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
            transition:0.3s;
        }

        .btn:hover{
            background:#0ea5e9;
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

            <?= $ips['ipv4']
                ? htmlspecialchars($ips['ipv4'], ENT_QUOTES, 'UTF-8')
                : '<span class="not-found">Not Detected</span>'
            ?>

        </div>

    </div>

    <div class="card">

        <div class="label">IPv6 Address</div>

        <div class="value">

            <?= $ips['ipv6']
                ? htmlspecialchars($ips['ipv6'], ENT_QUOTES, 'UTF-8')
                : '<span class="not-found">Not Detected</span>'
            ?>

        </div>

    </div>

    <a class="btn"
       href="?api=1"
       target="_blank">

        Open Secure JSON API

    </a>

    <div class="json-preview">

<pre><?= htmlspecialchars(
json_encode(
    $response,
    JSON_PRETTY_PRINT |
    JSON_UNESCAPED_SLASHES |
    JSON_UNESCAPED_UNICODE
),
ENT_QUOTES,
'UTF-8'
); ?></pre>

    </div>

    <div class="footer">
        Secure IPv4 / IPv6 Detection API
    </div>

</div>

</body>
</html>

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

/*
|--------------------------------------------------------------------------
| RATE LIMITING
|--------------------------------------------------------------------------
*/

builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter(
        policyName: "fixed",
        configureOptions: limiterOptions =>
        {
            limiterOptions.PermitLimit = 60;
            limiterOptions.Window = TimeSpan.FromMinutes(1);
            limiterOptions.QueueProcessingOrder =
                QueueProcessingOrder.OldestFirst;
            limiterOptions.QueueLimit = 0;
        });
});

/*
|--------------------------------------------------------------------------
| FORWARDED HEADERS
|--------------------------------------------------------------------------
*/

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
        Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor |
        Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto;

    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

var app = builder.Build();

/*
|--------------------------------------------------------------------------
| USE FORWARDED HEADERS
|--------------------------------------------------------------------------
*/

app.UseForwardedHeaders();

/*
|--------------------------------------------------------------------------
| SECURITY HEADERS
|--------------------------------------------------------------------------
*/

app.Use(async (context, next) =>
{
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";

    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; style-src 'self' 'unsafe-inline';";

    context.Response.Headers["Permissions-Policy"] =
        "geolocation=(), microphone=(), camera=()";

    await next();
});

/*
|--------------------------------------------------------------------------
| ENABLE RATE LIMITER
|--------------------------------------------------------------------------
*/

app.UseRateLimiter();

/*
|--------------------------------------------------------------------------
| MAIN ROUTE
|--------------------------------------------------------------------------
*/

app.MapGet("/", async (HttpContext context) =>
{
    /*
    |--------------------------------------------------------------------------
    | GET CLIENT IPS
    |--------------------------------------------------------------------------
    */

    string? ipv4 = null;
    string? ipv6 = null;

    List<string> possibleIps = new();

    /*
    |--------------------------------------------------------------------------
    | Cloudflare
    |--------------------------------------------------------------------------
    */

    if (context.Request.Headers.ContainsKey("CF-Connecting-IP"))
    {
        possibleIps.Add(
            context.Request.Headers["CF-Connecting-IP"].ToString()
        );
    }

    /*
    |--------------------------------------------------------------------------
    | Nginx Real IP
    |--------------------------------------------------------------------------
    */

    if (context.Request.Headers.ContainsKey("X-Real-IP"))
    {
        possibleIps.Add(
            context.Request.Headers["X-Real-IP"].ToString()
        );
    }

    /*
    |--------------------------------------------------------------------------
    | X-Forwarded-For
    |--------------------------------------------------------------------------
    */

    if (context.Request.Headers.ContainsKey("X-Forwarded-For"))
    {
        var forwardedIps =
            context.Request.Headers["X-Forwarded-For"]
                .ToString()
                .Split(',');

        foreach (var ip in forwardedIps)
        {
            possibleIps.Add(ip.Trim());
        }
    }

    /*
    |--------------------------------------------------------------------------
    | Remote Address
    |--------------------------------------------------------------------------
    */

    var remoteIp =
        context.Connection.RemoteIpAddress?.ToString();

    if (!string.IsNullOrWhiteSpace(remoteIp))
    {
        possibleIps.Add(remoteIp);
    }

    /*
    |--------------------------------------------------------------------------
    | VALIDATE IPS
    |--------------------------------------------------------------------------
    */

    foreach (var ip in possibleIps)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            continue;
        }

        string cleanedIp = ip.Replace("::ffff:", "");

        if (!IPAddress.TryParse(cleanedIp, out IPAddress? parsedIp))
        {
            continue;
        }

        /*
        |--------------------------------------------------------------------------
        | Detect IPv4
        |--------------------------------------------------------------------------
        */

        if (
            parsedIp.AddressFamily == AddressFamily.InterNetwork
            && ipv4 == null
        )
        {
            ipv4 = cleanedIp;
        }

        /*
        |--------------------------------------------------------------------------
        | Detect IPv6
        |--------------------------------------------------------------------------
        */

        if (
            parsedIp.AddressFamily == AddressFamily.InterNetworkV6
            && ipv6 == null
        )
        {
            ipv6 = cleanedIp;
        }
    }

    /*
    |--------------------------------------------------------------------------
    | SAFE USER AGENT
    |--------------------------------------------------------------------------
    */

    string userAgent =
        context.Request.Headers.UserAgent
            .ToString()
            .Replace("<", "")
            .Replace(">", "");

    if (userAgent.Length > 300)
    {
        userAgent = userAgent[..300];
    }

    /*
    |--------------------------------------------------------------------------
    | RESPONSE OBJECT
    |--------------------------------------------------------------------------
    */

    var response = new
    {
        success = true,

        ipv4 = ipv4,

        ipv6 = ipv6,

        ip_version = ipv6 != null
            ? "IPv6"
            : "IPv4",

        user_agent = userAgent,

        request_time = DateTime.UtcNow.ToString("o"),

        server = new
        {
            software = ".NET 8 ASP.NET Core",

            protocol = context.Request.Protocol
        }
    };

    /*
    |--------------------------------------------------------------------------
    | JSON API MODE
    |--------------------------------------------------------------------------
    */

    if (
        context.Request.Query["api"] == "1"
        ||
        context.Request.Query["format"] == "json"
    )
    {
        context.Response.ContentType =
            "application/json";

        await context.Response.WriteAsync(
            JsonSerializer.Serialize(
                response,
                new JsonSerializerOptions
                {
                    WriteIndented = true
                }
            )
        );

        return;
    }

    /*
    |--------------------------------------------------------------------------
    | HTML PAGE
    |--------------------------------------------------------------------------
    */

    string jsonPreview =
        JsonSerializer.Serialize(
            response,
            new JsonSerializerOptions
            {
                WriteIndented = true
            }
        );

    string html = $@"
<!DOCTYPE html>
<html lang='en'>

<head>

<meta charset='UTF-8'>

<meta name='viewport'
      content='width=device-width, initial-scale=1.0'>

<title>What Is My IP</title>

<style>

*{{
    box-sizing:border-box;
}}

body{{
    margin:0;
    padding:20px;
    font-family:Arial,sans-serif;
    background:#0f172a;
    color:white;
    display:flex;
    justify-content:center;
    align-items:center;
    min-height:100vh;
}}

.container{{
    width:100%;
    max-width:750px;
    background:#1e293b;
    border-radius:20px;
    padding:40px;
    box-shadow:0 0 30px rgba(0,0,0,0.4);
}}

h1{{
    text-align:center;
    color:#38bdf8;
    margin-bottom:35px;
}}

.card{{
    background:#0f172a;
    padding:20px;
    border-radius:14px;
    margin-bottom:20px;
    border-left:5px solid #38bdf8;
}}

.label{{
    color:#94a3b8;
    margin-bottom:10px;
    font-size:14px;
}}

.value{{
    font-size:22px;
    font-weight:bold;
    word-break:break-word;
}}

.not-found{{
    color:#f87171;
}}

.btn{{
    display:block;
    text-align:center;
    text-decoration:none;
    background:#38bdf8;
    color:#000;
    padding:15px;
    border-radius:12px;
    font-weight:bold;
    margin-top:25px;
}}

.json-preview{{
    margin-top:30px;
    background:#020617;
    padding:20px;
    border-radius:12px;
    overflow:auto;
}}

pre{{
    margin:0;
    color:#4ade80;
    font-size:14px;
    white-space:pre-wrap;
    word-break:break-word;
}}

.footer{{
    margin-top:25px;
    text-align:center;
    color:#94a3b8;
    font-size:13px;
}}

</style>

</head>

<body>

<div class='container'>

<h1>🌍 What Is My IP</h1>

<div class='card'>

<div class='label'>IPv4 Address</div>

<div class='value'>
{ipv4 ?? "<span class='not-found'>Not Detected</span>"}
</div>

</div>

<div class='card'>

<div class='label'>IPv6 Address</div>

<div class='value'>
{ipv6 ?? "<span class='not-found'>Not Detected</span>"}
</div>

</div>

<a class='btn'
   href='?api=1'
   target='_blank'>

Open Secure JSON API

</a>

<div class='json-preview'>

<pre>{WebUtility.HtmlEncode(jsonPreview)}</pre>

</div>

<div class='footer'>
Secure IPv4 / IPv6 Detection API
</div>

</div>

</body>
</html>
";

    context.Response.ContentType = "text/html";

    await context.Response.WriteAsync(html);

})
.RequireRateLimiting("fixed");

/*
|--------------------------------------------------------------------------
| START SERVER
|--------------------------------------------------------------------------
*/

app.Run("http://0.0.0.0:5000");

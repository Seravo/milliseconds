## Milliseconds

A Nginx access log parser.

First version takes an access log file as parameter, and outputs summary in JSON format. The JSON output is backwards compatible with the old Node.js based [Millseconds-js](https://github.com/Seravo/milliseconds-js).

> NOTE! This project is in very early stages and has known bugs and limitations, little error handling and no optimizations.

## Screenshot

```
$ milliseconds /var/log/nginx/hourly_total-access.log
{
    "total": {
        "count": 86550,
        "min": 0,
        "max": 60005,
        "avg": 219,
        "sum": 18999680,
        "bytes": 4253692819
    },
    "cache_none": {
        "count": 24956,
        "min": 0,
        "max": 60005,
        "avg": 384,
        "sum": 9593435,
        "bytes": 195533845
    },
    "cache_hit": {
        "count": 27112,
        "min": 0,
        "max": 413,
        "avg": 0,
        "sum": 9710,
        "bytes": 1295518694
    },
    "cache_miss": {
        "count": 32438,
        "min": 0,
        "max": 60000,
        "avg": 248,
        "sum": 8058946,
        "bytes": 2653299579
    },
    "cache_other": {
        "count": 2044,
        "min": 0,
        "max": 24296,
        "avg": 654,
        "sum": 1337589,
        "bytes": 109340701
    },
    "2xx": {
        "count": 65422,
        "min": 0,
        "max": 55514,
        "avg": 241,
        "sum": 15825874,
        "bytes": 4211003908
    },
    "3xx": {
        "count": 16454,
        "min": 0,
        "max": 26493,
        "avg": 87,
        "sum": 1437148,
        "bytes": 1989489
    },
    "4xx": {
        "count": 4619,
        "min": 0,
        "max": 60000,
        "avg": 356,
        "sum": 1647472,
        "bytes": 39998094
    },
    "5xx": {
        "count": 10,
        "min": 7,
        "max": 60005,
        "avg": 6231,
        "sum": 62316,
        "bytes": 23999
    },
    "503": {
        "count": 45,
        "min": 1,
        "max": 16445,
        "avg": 597,
        "sum": 26870,
        "bytes": 677329
    },
    "internal": {
        "count": 16848,
        "min": 0,
        "max": 55332,
        "avg": 263,
        "sum": 4445837,
        "bytes": 171980623
    },
    "top-hostname": {
        "aaa.fi": 3513,
        "bbb.fi": 2358,
        "www.bbb.fi": 1970,
        "ccc.fi": 1810,
        "ddd.fi": 1787,
        "eee.fi": 1625,
        "www.fff.com": 1593,
        "ggg.fi": 1202,
        "hhh.fi": 1136
    },
    "top-remote_addr": {
        "2a04:3542:aa:bb:cc:dd:ee:ff": 14979,
        "94.237.88.11": 1862,
        "92.220.77.22": 1314,
        "196.178.66.33": 746,
        "23.100.55.44": 700,
        "81.19.44.55": 579,
        "193.169.33.66": 568,
        "89.163.22.77": 496,
        "66.102.11.88": 464
    },
    "top-remote_user": {
        "-": 86252,
        "asdf": 257,
        "vbmn": 38,
        "qwer": 2,
        "zxcv": 1
    },
    "top-request_type": {
        "GET": 78310,
        "POST": 7265,
        "HEAD": 939,
        "OPTIONS": 17,
        "PURGE": 11,
        "DELETE": 8
    },
    "top-protocol": {
        "HTTP/1.1": 86550
    },
    "top-status": {
        "200": 65337,
        "301": 14925,
        "404": 2965,
        "304": 1100,
        "401": 789,
        "302": 403,
        "429": 304,
        "499": 273,
        "403": 179
    },
    "top-cache": {
        "MISS": 32438,
        "HIT": 27112,
        "BYPASS": 17656,
        "-": 7300,
        "STALE": 2040,
        "UPDATING": 4
    }
}
```

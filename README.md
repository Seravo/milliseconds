## Milliseconds

A Nginx access log parser.

First version takes an access log file as parameter, and outputs summary in JSON format. The JSON output is backwards compatible with the old Node.js based [Millseconds-js](https://github.com/Seravo/milliseconds-js).

> NOTE! This project is in very early stages and has known bugs and limitations, little error handling and no optimizations.

## Screenshot

```
$ milliseconds /var/log/nginx/hourly_total-access.log
{
    "total": {
        "num_requests": 6017,
        "min": 0,
        "max": 5119,
        "avg": 20,
        "sum": 124182
    },
    "cached": {
        "num_requests": 347,
        "min": 0,
        "max": 75,
        "avg": 1,
        "sum": 466
    },
    "uncached": {
        "num_requests": 5670,
        "min": 0,
        "max": 5119,
        "avg": 21,
        "sum": 123716
    },
    "php_total": {
        "num_requests": 0,
        "min": 0,
        "max": 0,
        "avg": 0,
        "sum": 0
    },
    "php_cached": {
        "num_requests": 0,
        "min": 0,
        "max": 0,
        "avg": 0,
        "sum": 0
    },
    "php_uncached": {
        "num_requests": 0,
        "min": 0,
        "max": 0,
        "avg": 0,
        "sum": 0
    },
    "static": {
        "num_requests": 6017,
        "min": 0,
        "max": 5119,
        "avg": 20,
        "sum": 124182
    },
    "internal": {
        "num_requests": 357,
        "min": 0,
        "max": 147,
        "avg": 31,
        "sum": 11112
    }
}
```

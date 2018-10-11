#!/usr/bin/python3
"""Nginx access log analyzer"""

import json
import sys
import re

from pprint import pprint


def add_counters(data, category):

    # Set baseline if first value
    if result[category]['num_requests'] == 0:
        result[category]['max'] = data['duration']
        result[category]['min'] = data['duration']

    if data['duration'] > result[category]['max']:
        result[category]['max'] = data['duration']

    if data['duration'] < result[category]['min']:
        result[category]['min'] = data['duration']

    # Increment counters
    result[category]['num_requests'] += 1
    result[category]['sum'] += data['duration']
    result[category]['avg'] = \
        int(result[category]['sum'] / result[category]['num_requests'])

    return result


bucket = {
    "num_requests": 0,
    "min": 0,
    "max": 0,
    "avg": 0,
    "sum": 0,
    #  "95th_percentile": 0
}
result = {
    "total": dict(bucket),
    "cached": dict(bucket),
    "uncached": dict(bucket),
    "php_total": dict(bucket),
    "php_cached": dict(bucket),
    "php_uncached": dict(bucket),
    "static": dict(bucket),
    "internal": dict(bucket)
}

lineformat = (r''
              '(?P<hostname>[^ ]+) '
              '(?P<remote_addr>[^ ]+) '
              '- '
              '(?P<remote_user>[^ ]+) '
              '\[(?P<time>.+)\] '
              '"(?P<request_type>[A-Z]+) '
              '(?P<request_url>[^ ]+) '
              '(?P<protocol>[^ ]+)" '
              '(?P<status>[0-9]+) '
              '(?P<bytes>[0-9]+) '
              '"(?P<referer>[^"]+)" '
              '"(?P<user_agent>[^"]*)" '
              '(?P<cache>[A-Z-]+) '
              '(?P<php>[^ ]+) '
              '(?P<duration>[0-9\.]+)\n'
              )

lineregex = re.compile(lineformat)
linecounter = 0


if __name__ == '__main__':
    # pprint(result)

    # Open input CSV and interate all lines
    with open(sys.argv[1], 'r') as f:

        for l in f.readlines():
            linecounter += 1

            match = re.search(lineformat, l)

            if not match:
                print("Unexpected log line contents:")
                pprint(l)
                sys.exit(1)
            else:
                data = match.groupdict()

            if len(data) != 14:
                print("Unexpected log line length: %d" % len(data))
                pprint(l)
                sys.exit(1)
            else:
                # print("Line %d: 15 items" % linecounter)
                pass

            # if data and linecounter > 9995:
            #    pprint(data)

            # Analyze line and update counters
            if data:
                # Convert to milliseconds
                data['duration'] = int(float(data['duration']) * 1000)
                add_counters(data, 'total')

            if data['php'] == '-':
                add_counters(data, 'php_total')

                if 'HIT' in data['cache']:
                    add_counters(data, 'php_cached')
                else:
                    add_counters(data, 'php_uncached')
            else:
                add_counters(data, 'static')

            if 'HIT' in data['cache']:
                add_counters(data, 'cached')
            else:
                add_counters(data, 'uncached')

            if 'Zabbix' in data['user_agent'] or \
               'SWD' in data['user_agent'] or \
               '400' == data['status'] or \
               '408' == data['status']:
                add_counters(data, 'internal')

        print(json.dumps(result, indent=4))

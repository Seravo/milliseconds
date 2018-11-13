#!/usr/bin/python3
"""Nginx access log analyzer"""

import json
import sys
import re

from pprint import pprint


def add_counters(data, category):

    # Set baseline if first value
    if result[category]['count'] == 0:
        result[category]['max'] = data['duration']
        result[category]['min'] = data['duration']

    if data['duration'] > result[category]['max']:
        result[category]['max'] = data['duration']

    if data['duration'] < result[category]['min']:
        result[category]['min'] = data['duration']

    # Increment counters
    result[category]['count'] += 1
    result[category]['sum'] += data['duration']
    result[category]['avg'] = \
        int(result[category]['sum'] / result[category]['count'])

    result[category]['bytes'] += data['bytes']

    return result


def get_top_10(result_type, result_type_dict):
    result = dict()
    for entry in sorted(
            result_type_dict,
            key=result_type_dict.__getitem__,
            reverse=True)[0:9]:

        result[entry] = result_types[result_type][entry]

    return result


bucket = {
    'count': 0,
    'min': 0,
    'max': 0,
    'avg': 0,
    'sum': 0,
    'bytes': 0,
    #  '95th_percentile': 0
}
result = {
    'total': dict(bucket),
    'cache_none': dict(bucket),
    'cache_hit': dict(bucket),
    'cache_miss': dict(bucket),
    'cache_other': dict(bucket),
    '2xx': dict(bucket),
    '3xx': dict(bucket),
    '4xx': dict(bucket),
    '5xx': dict(bucket),
    'internal': dict(bucket)
}

result_types = {
  'request_type': dict(),
  'protocol': dict(),
  'status': dict(),
  'cache': dict(),
  'server': dict(),
  'hostname': dict()
}

lineformat = (r''
              '(?P<hostname>[^ ]+) '
              '(?P<remote_addr>[^ ]+) '
              '- '
              '(?P<remote_user>[^ ]+) '
              '\[(?P<time>.+)\] '
              '"(?P<request_type>[A-Z_]+) '  # Clients can name their methods whatever, e.g. CCM_POST
              '(?P<request_url>[^ ]+) '
              '(?P<protocol>[^ ]+)" '
              '(?P<status>[0-9]+) '
              '(?P<bytes>[0-9]+) '
              '"(?P<referer>[^"]*)" '
              '"(?P<user_agent>[^"]*)" '
              '(?P<cache>[A-Z-]+) '
              '"(?P<server>[^"]+)" '
              '(?P<duration>[0-9\.]+)\n'
              )

lineregex = re.compile(lineformat)
linecounter = 0


if __name__ == '__main__':

    # Open input log and interate all lines
    with open(sys.argv[1], 'r') as f:

        for l in f.readlines():
            linecounter += 1

            match = re.search(lineformat, l)

            if not match:
                print('Unexpected log line contents:')
                pprint(l)
                sys.exit(1)
            else:
                data = match.groupdict()

            if len(data) != 14:
                print('Unexpected log line length: %d' % len(data))
                pprint(l)
                sys.exit(1)

            # Collect each unique data type
            for type in result_types.keys():
                if data[type] not in result_types[type]:
                    result_types[type][data[type]] = 1
                else:
                    result_types[type][data[type]] += 1

            # Analyze line and update counters
            if data:
                # Convert to milliseconds
                data['duration'] = int(float(data['duration']) * 1000)
                data['bytes'] = int(data['bytes'])
                add_counters(data, 'total')

            if '-' in data['cache'] or 'BYPASS' in data['cache']:
                add_counters(data, 'cache_none')
            elif 'HIT' in data['cache']:
                add_counters(data, 'cache_hit')
            elif 'MISS' in data['cache']:
                add_counters(data, 'cache_miss')
            else:
                add_counters(data, 'cache_other')

            status_class = data['status'][0]
            add_counters(data, status_class + 'xx')

            if 'Zabbix' in data['user_agent'] or 'SWD' in data['user_agent']:
                add_counters(data, 'internal')

        # Extend results with top-10 lists for each result type
        for result_type in result_types:
            result['top-' + result_type] = get_top_10(result_type, result_types[result_type])

        # Output results
        print(json.dumps(result, indent=4))

        # Debug: print log data types
        debug = False
        if debug:
            print('Total lines analyzed: %d' % linecounter)
            print('Total requests calculated: %d' % result['total']['count'])

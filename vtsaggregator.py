# A monitoring tool for aggregating stats from nginx-module-vts plugin
#
# @TODO: Aggregate statistics from multiple backends, i.e. cluster support
# @TODO: Online plotting for debugging/development
# @TODO: Test aggregation by plotting scraped data from the test cluster

import argparse
import ast
from collections import defaultdict, deque
import copy
import json
import math
import os
import pprint
from sortedcontainers import SortedDict
import sys
import time
import traceback
import urllib
import urllib3
from typing import List, Set

from typevalidator import ZERO_OR_MORE, OPTIONAL_KEY, validate2

DESCRIPTION = """
A monitoring tool for aggregating stats from Nginx Vhost Traffic Status plugin.
See https://github.com/vozlt/nginx-module-vts.

Usage in short:

To start monitoring aggregation on the foreground, run:

$ python3 vtsaggregator.py https://host/vts-prefix/format/json \\
    --milliseconds milliseconds.json --checkpoint checkpoint-file

Both milliseconds.json and checkpoint-file can be non-existent files, but they
must be given. The tool writes the aggregated monitoring metrics to
milliseconds.json at each interval. Persistent state is saved to the
checkpoint-file so that the tool can be safely restarted
(not losing data points).

nginx-module-vts exports monotonically increasing counters and other
variables. A counter only decreases if there is an integer overflow or the
nginx is restarted.

The statistics are generated from the counters of the following types:
* Number of requests received (so far in the lifetime of the plugin)
* Number of bytes received and sent
* Number of milliseconds consumed for processing requests

These counters are repeatedly fetched from the plugin in regular intervals.
Meaningful monitoring values are obtained by comparing similar counters
between consecutive intervals. In essence, the difference between values of
consecutive intervals matters.

Values from multiple counters can be aggregated together (summed) to
create summary statistics (e.g. 404 and 429 code counters together form 4xx
status code counter).

There can be monitoring variables where the difference is not relevant,
but they are not currently. An example of such variable is healthiness
variable that 'gauges' whether a backend is healthy at the moment or not.

Measures that are meaningful for monitoring from user point of view
are called 'metrics'. E.g. number of requests per second.

# Testing with offline data

Collect 7 data points (json files) 10 seconds apart for offline testing:

$ rm -f testcheckpoint
$ python3 vtsaggregator.py https://host/prefix/format/json \\
    --interval 10 --checkpoint testcheckpoint \\
    --milliseconds milliseconds.json --verbose --stat-dir . --test-limit 7

If you omit --test-limit, it will collect files indefinitely. The json files
are named '{host}-000001.json', '{host}-000002.json', ...

To test json files that were collected:

$ rm -f testcheckpoint
$ python3 vtsaggregator.py \\
    --interval 10 --milliseconds milliseconds.json \\
    --checkpoint testcheckpoint --test-mode --plot --plot-zones 2xx foo-*.json

where y is the value chosen in collection.
"""

VERSION = '1.0.0'

ZONE_TO_MILLISECONDS = {
    'BYPASS': 'cache_none',
    'MISS': 'cache_miss',
    'HIT': 'cache_hit',
    'NO_CACHE': 'cache_no_cache',
    }

# Note: 'PURGE' is not part of the HTTP standard, but it is used by some
# caching systems like pagespeed
HTTP_REQUEST_METHODS = set([
    'CONNECT', 'DELETE', 'GET', 'HEAD', 'PATCH', 'POST', 'PURGE', 'PUT',
    'TRACE', 'OPTIONS',
    ])

# Cache zones are named in nginx directory src/http/ngx_http_cache.h
CACHE_OTHER_ZONES = set([
    'EXPIRED', 'REVALIDATED', 'SCARCE', 'STALE', 'UPDATING'])
CACHE_ZONES = set(['BYPASS', 'HIT', 'MISS', 'NO_CACHE']).union(
    CACHE_OTHER_ZONES)

# Timeseries attribute to define a histogram
HISTOGRAM_ATTR = 'le'

# Timeseries attribute-value pairs that are commonly used
UNIT_BYTES = ('unit', 'bytes')
UNIT_REQUESTS = ('unit', 'requests')
UNIT_SECONDS = ('unit', 's')

CHECKPOINT_FMT = {
    'timeseries': [ZERO_OR_MORE, {
        'key_dict': {
            'name': str,
            'backend': str,
            'zone': str,
            OPTIONAL_KEY('le'): float,
            },
        'data': [ZERO_OR_MORE, tuple],
        },
        ],
    't_prev': float,
    }

LOG_DIR = None


class ConfigError(Exception):
    pass


def _write_log_entry(log_entry):
    if LOG_DIR is None:
        return
    log_name = os.path.join(LOG_DIR, 'vtsaggregator.log')
    log_line = repr(log_entry) + '\n'
    try:
        with open(log_name, 'a') as f:
            f.write(log_line)
    except OSError as e:
        print('Unable to open or write a log entry:', e)
        return


def _args_to_prefix(*args):
    return ' '.join([str(x) for x in args])


def log_exception(e, *args):
    msg = _args_to_prefix(*args)
    log_entry = {
        'type': 'exception',
        'argv': sys.argv,
        'exc': traceback.format_exc(),
        'msg': msg,
        }
    print('{}\n\n{}'.format(msg, log_entry['exc']))
    _write_log_entry(log_entry)


def log_error(*args):
    msg = _args_to_prefix(*args)
    log_entry = {
        'type': 'error',
        'argv': sys.argv,
        'msg': msg,
        }
    print('Error: {}'.format(msg))
    _write_log_entry(log_entry)


def log_warning(*args):
    msg = _args_to_prefix(*args)
    log_entry = {
        'type': 'warning',
        'argv': sys.argv,
        'msg': msg,
        }
    print('Warning: {}'.format(msg))
    _write_log_entry(log_entry)


def key_dict_to_tuple(key_dict):
    return tuple(sorted(key_dict.items()))


def _dict_inserted_in_top_order(d):
    # Since Python 3.6, insertion is preserved with dictionaries. We exploit
    # that.

    def _tuple_or_none_key(key):
        if key[1] is None:
            return 0
        return key[1]

    sorted_d = {}
    for k, v in sorted(d.items(), key=_tuple_or_none_key, reverse=True):
        sorted_d[k] = v

    return sorted_d


class TimeSeries:
    def __init__(self, key: dict):
        self.key_dict = key
        self._data = deque(maxlen=2)

    def add(self, t, value, overflow_limit=(1 << 52)):
        # JavaScript/JSON limitation
        if value >= overflow_limit:
            if isinstance(value, int):
                value &= (overflow_limit - 1)
            elif isinstance(value, float):
                value = math.fmod(value, overflow_limit)
        self._data.append((t, value))

    def drop_everything_but_latest(self):
        if len(self._data) > 1:
            latest = self._data[-1]
            self._data.clear()
            self._data.append(latest)

    def sum(self, other: 'TimeSeries'):
        if len(other) == 0:
            return
        t_other, value_other = other._data[-1]
        if len(self) == 0:
            # a new point in time
            self.add(t_other, value_other)
            return
        t = self._data[-1][0]
        if t_other < t:
            # an old point in time. drop.
            return
        elif t_other > t:
            # a new point in time
            self.add(t_other, value_other)
        else:
            # the same point in time: sum counters together
            value = self._data[-1][1]
            self._data[-1] = (t, value + value_other)

    def get_diff(self, interval: int, mutable: bool):
        if len(self._data) < 2:
            return None
        data_prev = self.get_data(-2)
        data_latest = self.get_data(-1)

        tdelta = data_latest[0] - data_prev[0]
        if tdelta > (2.5 * interval):
            # The counter diff is over 2.5 intervals in time,
            # and thus not accurate. Return no result.
            return None

        diff = data_latest[1] - data_prev[1]  # counter diff
        if diff < 0.0:
            if mutable:
                self.drop_everything_but_latest()
            return None
        return diff

    def get_data(self, index: int):
        # index == -1 is the latest value, index == -2 is the second latest, ..
        # index must be < 0
        assert index < 0
        return self._data[index]

    def serialize(self):
        return copy.deepcopy({'key_dict': self.key_dict,
                              'data': list(self._data),
                              })

    @classmethod
    def unserialize(cls, d) -> 'TimeSeries':
        ts = cls(d['key_dict'])
        for tup in d['data']:
            ts.add(*tup)
        return ts

    def __len__(self):
        return len(self._data)

    def __str__(self):
        return 'TimeSeries({}, {})'.format(self.key_dict, self._data)


class Histogram:
    def __init__(self, key_dict: dict):
        # List all timeseries key-tuples of a histogram
        self._timeseries = set()
        # Map histogram le value to timeseries key_tuple
        self._les = SortedDict()
        self.key_dict = key_dict

    def add(self, key_tuple: dict):
        if key_tuple in self._timeseries:
            return
        self._timeseries.add(key_tuple)
        for attribute, value in key_tuple:
            if attribute == HISTOGRAM_ATTR:
                self._les[value] = key_tuple
                return
        assert False

    def get_percentiles(self, timeseries, latency_percentiles, interval):
        # Get percentiles for statistics between the last two measurements.
        # ts.get_diff() returns the difference between them.
        counts = []
        for le, key_tuple in self._les.items():
            ts = timeseries[key_tuple]
            count = ts.get_diff(interval, False)
            if count is None:
                return None
            assert count >= 0
            if len(counts) > 0 and count < counts[-1][1]:
                log_error('Bad data: decreasing counter counts', le, key_tuple)
                return None
            counts.append((le, count))

        # In the cumulative frequency distribution, the highest latency bucket
        # is the total number of requests during the last monitoring interval.
        num_requests = counts[-1][1]
        if num_requests == 0:
            return {}

        percentile_values = {}
        for p in latency_percentiles:
            target_count = max(int(p * num_requests), 1)
            i = 0
            for le, count in counts:
                if count >= target_count:
                    break
                i += 1
            if i == 0:
                low_le = 0.0
                low_count = 0
            else:
                low_le, low_count = counts[i - 1]
            high_le, high_count = counts[i]
            assert high_count > low_count
            t = (target_count - low_count) / (high_count - low_count)
            latency = low_le + t * (high_le - low_le)
            percentile_values[p] = latency
        return percentile_values

    def __iter__(self):
        return iter(self._timeseries)


def parse_from_key_tuple(key_tuple, attribute):
    for tuple_attribute, value in key_tuple:
        if tuple_attribute == attribute:
            return value
    return None


def _strip_jsonp_prefix(data):
    # Remove JSONP prefix, if exists
    JSONP_PREFIX = 'ngx_http_vhost_traffic_status_jsonp_callback('
    if data.startswith(JSONP_PREFIX) and data[-1] == ')':
        data = data[len(JSONP_PREFIX):-1]
    return data


class State:
    def __init__(self, args):
        # self._timeseries maps key-tuple to TimeSeries object
        #
        # key-tuple defines a name of a timeseries, e.g.:
        #   (('backend', 'server_name'), (HISTOGRAM_ATTR, 0.001),
        #    ('name', 'response_duration'), ('zone', 'MISS'),
        #    ('unit', 's'))
        self._timeseries = {}

        # self._histograms maps histogram-tuple to Histogram. histogram-tuple
        # is a reduced key-tuple so that the histogram-tuple defines a name for
        # all key-tuples of a histogram.
        #
        # E.g. histogram-tuple is (('backend', 'server_name'),
        #                          ('name', 'response_duration'),
        #                          ('zone', 'MISS'),
        #                          ('unit', 's'))
        #
        # The histogram contains multiple key-tuples each with different
        # value for HISTOGRAM_ATTR.
        self._histograms = {}

        if len(args.urls) == 0:
            log_warning('No URLs given')

        urls = set()
        for url in args.urls:
            if url in urls:
                raise ConfigError('Duplicate URL {} given'.format(url))
            urls.add(url)

        # Create urllib3 PoolManager for monitoring connections
        kwargs = {
            'num_pools': len(args.urls),
            'timeout': args.timeout,
            'retries': False,  # No retries,  just lose the data
            }
        if args.insecure:
            kwargs['cert_reqs'] = 'CERT_NONE'
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self._http = urllib3.PoolManager(**kwargs)

        self._zones = []
        for zone in args.zones.split(','):
            zone = zone.strip()
            if len(zone) > 0:
                self._zones.append(zone)

        self._latency_percentiles = []
        for percentile in args.latency_percentiles.split(','):
            p = float(percentile) / 100.0
            if p < 0.0 or p > 1.0:
                raise ConfigError('Invalid percentile value:', percentile)
            self._latency_percentiles.append(p)
        if len(self._latency_percentiles) == 0:
            log_warning('No latency percentiles computed')

        if args.plot:
            # Map (plot_type, key_tuple) to a list of percentile values
            self._plots = defaultdict(list)

        # Map backend url to (t, milliseconds_dict)
        self._stats = {}
        self._interval = args.interval
        self._t_prev = -1.0

        self._verbose_zones = []
        if args.verbose_zones is None:
            self._verbose_zones.append('total')
        else:
            for zone in args.verbose_zones.split(','):
                self._verbose_zones.append(zone.strip())

        self._checkpoint = args.checkpoint
        self._milliseconds = args.milliseconds

    def _get_stat_zones(self, backend, backend_stats):
        """If zones are given as arguments, only get stats for them.

        Otherwise, get stats for all zones listed inside serverZones.
        """

        zones = self._zones
        if len(zones) == 0:
            try:
                zones = list(backend_stats['serverZones'])
            except KeyError as e:
                log_exception(e, 'serverZones is not defined for', backend)
                zones = None
        return zones

    def _get_timeseries(self, key_dict: dict, create=False):
        """Get or create a timeseries.

        A histogram is object is created if a timeseries has an HISTOGRAM_ATTR
        attribute, the histogram does not already exist, and create is True.
        """
        if 'name' not in key_dict:
            raise ValueError('name missing in key')
        key_tuple = key_dict_to_tuple(key_dict)

        ts = self._timeseries.get(key_tuple)
        if ts is None:
            if not create:
                raise IndexError('TimeSeries tuple {} does not exist'.format(
                    key_tuple))
            ts = self._timeseries.setdefault(key_tuple, TimeSeries(key_dict))

        self._create_histogram(key_dict)
        return ts

    def _key_to_histogram_tuple(self, key):
        histogram_key = dict(key)
        histogram_key.pop(HISTOGRAM_ATTR)
        return tuple(sorted(histogram_key.items()))

    def _create_histogram(self, key_dict):
        if HISTOGRAM_ATTR not in key_dict:
            return
        # Create a fast index for histograms. Combine all timeseries of a
        # histogram into a list.
        histogram_key = dict(key_dict)
        histogram_key.pop(HISTOGRAM_ATTR)
        histogram_tuple = tuple(sorted(histogram_key.items()))

        if histogram_tuple not in self._histograms:
            self._histograms[histogram_tuple] = Histogram(histogram_key)
        key_tuple = key_dict_to_tuple(key_dict)
        self._histograms[histogram_tuple].add(key_tuple)

    def _get_timeseries_diff(self, key_dict: dict, mutable: bool):
        try:
            ts = self._get_timeseries(key_dict)
        except IndexError:
            return None
        return ts.get_diff(self._interval, mutable)

    def _key_dict(self, name, backend, zone, *key_values):
        key_dict = {'name': name, 'backend': backend, 'zone': zone}
        for k, v in key_values:
            key_dict[k] = v
        return key_dict

    def _key_tuple(self, name, backend, zone, *key_values):
        key_dict = self._key_dict(name, backend, zone, *key_values)
        return key_dict_to_tuple(key_dict)

    def load(self):
        try:
            data = open(self._checkpoint).read()
        except FileNotFoundError:
            log_warning('Checkpoint', self._checkpoint, 'does not exist')
            return

        try:
            d = ast.literal_eval(data)
        except SyntaxError as e:  # Really!
            log_exception(e, 'Unable to parse {}'.format(self._checkpoint))
            return

        try:
            validate2(CHECKPOINT_FMT, d)
        except ValueError as e:
            log_exception(e, 'Checkpoint {} invalid'.format(self._checkpoint))
            return

        for serialized_ts in d['timeseries']:
            ts = TimeSeries.unserialize(serialized_ts)
            key_tuple = key_dict_to_tuple(ts.key_dict)
            self._timeseries[key_tuple] = ts
            self._create_histogram(ts.key_dict)
        self._t_prev = d['t_prev']

    def save(self):
        """Write checkpoint file atomically to avoid invalid data on disk."""
        tses = []
        for ts in self._timeseries.values():
            tses.append(ts.serialize())
        s = repr({
            'timeseries': tses,
            't_prev': self._t_prev,
            })
        # 1. Write the data to a temp file
        tmpname = self._checkpoint + '.tmp'
        with open(tmpname, 'w') as f:
            f.write(s)
        # 2. Rename temp file as the checkpoint file
        os.rename(tmpname, self._checkpoint)

    def fetch_backend_data(self, urls: List[str], args):
        backend_data = []
        for url in urls:
            if url.startswith('http://') or url.startswith('https://'):
                try:
                    req = self._http.request('GET', url)
                except urllib3.exceptions.ConnectTimeoutError as e:
                    log_exception(e, 'Request timeout for URL {}'.format(url))
                    continue
                except urllib3.exceptions.HTTPError as e:
                    log_exception(e, 'Request failed for URL {}'.format(url))
                    continue
                if req.status != 200:
                    log_error('HTTP status != 200 for URL {}: {}'.format(
                        url, req.reason))
                    continue
                data = req.data
                backend = url
            else:
                data = open(url, 'rb').read()
                backend = os.path.dirname(url)

            backend_data.append((backend, data))

        return backend_data

    def aggregate_backend_data(self, t_cur: float, backend_data: list, args):
        # Note: it is critical for counter aggregation that the same value for
        # t_cur is used for every backend and timeseries collected
        # for the same interval.
        milliseconds_stats = {}

        if args.test_mode:
            t_cur = None

        for backend, data in backend_data:
            try:
                data = data.decode()
            except UnicodeDecodeError:
                log_error('Invalid UTF-8:', data)
                continue
            data = _strip_jsonp_prefix(data)

            try:
                backend_stats = json.loads(data)
            except json.JSONDecodeError as e:
                log_exception(
                    e,
                    'JSON from URL {} is not valid. A wrong URL was '
                    'probably given. A valid URL should probably end with '
                    '/format/json'.format(backend))
                continue

            zones = self._get_stat_zones(backend, backend_stats)
            if zones is None:
                continue

            updated_ts = []
            for zone in zones:
                try:
                    if t_cur is None:
                        assert args.test_mode
                        # In test mode, get the current timestamp from json
                        # that was loaded from a server
                        t_cur = backend_stats['nowMsec'] / 1000

                    self._parse_zone(updated_ts, t_cur, backend,
                                     backend_stats, zone)
                except (KeyError, IndexError, ValueError) as e:
                    log_exception(e, 'Parse error on zone {}'.format(zone))
                    continue

            status_code_zones = self._aggregate_zones(updated_ts)

            # Get combined statistics for the backend at t_cur
            backend_metrics = self._get_backend_metrics(
                t_cur, backend, updated_ts, status_code_zones)

            milliseconds_stats[backend] = {
                't': t_cur,
                'metrics': backend_metrics,
                }

            # For testing
            if args.verbose:
                self._print_backend_metrics(backend_metrics)
            if args.plot:
                self._plot_backend_metrics(t_cur)

        if self._milliseconds is not None:
            # Write milliseconds stats into a json file for a monitor client
            tmpname = self._milliseconds + '.tmp'
            with open(tmpname, 'w') as f:
                f.write(json.dumps(milliseconds_stats))
            os.rename(tmpname, self._milliseconds)

        assert t_cur is not None
        self._t_prev = t_cur

    def _plot_backend_metrics(self, t_cur):
        for key_tuple, ts in self._timeseries.items():
            key_dict = dict(key_tuple)
            if HISTOGRAM_ATTR in key_dict:
                histogram_tuple = self._key_to_histogram_tuple(key_tuple)
                histogram = self._histograms[histogram_tuple]
                percentile_values = histogram.get_percentiles(
                    self._timeseries, self._latency_percentiles,
                    self._interval)
                self._plots[('histogram', histogram_tuple)].append(
                    (t_cur, percentile_values))
                continue
            plot_type = None
            if 'direction' in key_dict:
                plot_type = 'bytes'
            elif key_dict.get('unit', '') == 'requests':
                plot_type = 'requests'
            if plot_type is None:
                continue
            value = ts.get_diff(self._interval, False)
            if value is not None:
                value /= self._interval
                self._plots[(plot_type, key_tuple)].append((t_cur, value))

    def _print_backend_metrics(self, backend_metrics):
        zones = self._verbose_zones
        if '*' in zones:
            zones = sorted(backend_metrics)
        for zone in zones:
            print('zone {}:'.format(zone))
            pprint.pprint(backend_metrics[zone])

    def _get_backend_metrics(self, t_cur, backend: str,
                             updated_ts: List[TimeSeries],
                             status_code_zones: Set[str]):
        """Generate a backend stats report in milliseconds format"""

        # Get unique zones from updated timeseries
        zones = set()
        for ts in updated_ts:
            zones.add(ts.key_dict['zone'])

        # Collect total number of requests per http status code
        status_code_stats = {}
        for status_code_zone in status_code_zones:
            status_code_stats[status_code_zone] = 0
        # Collect total number of requests per http request method
        method_stats = {}
        # Collect total number of requests per http protocol
        protocol_stats = {}
        # Collect total number of cache events (HIT, MISS, NO_CACHE, ...)
        cache_stats = {}

        rate_postfix = 'rate{}s'.format(self._interval)

        d = {}
        for zone in sorted(zones):
            ms = ZONE_TO_MILLISECONDS.get(zone, zone)
            stats = {}
            d[ms] = stats
            # Data uploaded to clients
            stats['bytes'] = self._get_timeseries_diff(
                self._key_dict('bytes', backend, zone, ('direction', 'out'),
                               UNIT_BYTES),
                True)
            # Data uploaded to server
            stats['bytes_in'] = self._get_timeseries_diff(
                self._key_dict('bytes', backend, zone, ('direction', 'in'),
                               UNIT_BYTES),
                True)
            count_diff = self._get_timeseries_diff(
                self._key_dict('requests_total', backend, zone, UNIT_REQUESTS),
                True)
            sum_diff = self._get_timeseries_diff(
                self._key_dict('response_duration_sum', backend, zone,
                               UNIT_SECONDS),
                True)
            stats['count'] = count_diff

            if zone in status_code_stats:
                status_code_stats[zone] = count_diff
            if zone in HTTP_REQUEST_METHODS:
                method_stats[zone] = count_diff
            if zone.startswith('HTTP/'):
                protocol_stats[zone] = count_diff
            if zone in CACHE_ZONES:
                cache_stats[zone] = count_diff

            stats['sum'] = None
            stats['avg'] = None
            if sum_diff is not None:
                stats['sum'] = round(sum_diff * 1000)
                if count_diff is not None:
                    stats['avg'] = round(sum_diff * 1000 /
                                         max(1, stats['count']))
            if self._t_prev is not None and t_cur > self._t_prev:
                for name in ('bytes', 'bytes_in', 'count', 'sum'):
                    value = stats[name]
                    rate_name = '{}:{}'.format(name, rate_postfix)
                    if value is None:
                        stats[rate_name] = None
                    else:
                        rate = value / (t_cur - self._t_prev)
                        stats[rate_name] = int(rate * 100) / 100

        for histogram in self._histograms.values():
            zone = histogram.key_dict['zone']
            percentile_values = histogram.get_percentiles(
                self._timeseries, self._latency_percentiles, self._interval)
            if percentile_values is None or len(percentile_values) == 0:
                continue
            ms = ZONE_TO_MILLISECONDS.get(zone, zone)
            for p in self._latency_percentiles:
                if p not in percentile_values:
                    continue
                key = 'p{:02d}'.format(round(100 * p))
                if p == 0.0:
                    key = 'min'
                elif p == 1.0:
                    key = 'max'
                if percentile_values is None:
                    d[ms][key] = None
                else:
                    # In milliseconds
                    value = round(percentile_values[p] / 0.001)
                    d[ms][key] = value

        d['top-status'] = _dict_inserted_in_top_order(status_code_stats)
        d['top-request_type'] = _dict_inserted_in_top_order(method_stats)
        d['top-protocol'] = _dict_inserted_in_top_order(protocol_stats)
        d['top-cache'] = _dict_inserted_in_top_order(cache_stats)
        return d

    def _create_data_point(self,
                           updated_ts: List[TimeSeries],
                           key_dict: dict,
                           value,
                           t):
        ts = self._get_timeseries(key_dict, create=True)
        ts.add(t, value)
        updated_ts.append(ts)

    def _aggregate_zones(self, updated_ts: List[TimeSeries]):
        # Aggregate 2xx, 3xx, ... status code zones into
        # '2xx', '3xx', ... zones.
        #
        # Also, aggregate all status codes into a 'total' zone.
        #
        # Also, aggregate CACHE_OTHER_ZONES as cache_other.
        #
        # Example: '4xx' timeseries are created by summing counters of
        # '404' and '429' timeseries.
        agg_tses = set()
        status_code_zones = set()

        for ts in updated_ts:
            zone = ts.key_dict.get('zone')
            if zone is None:
                continue

            if zone in CACHE_OTHER_ZONES:
                cache_other_key_dict = dict(ts.key_dict)
                cache_other_key_dict['zone'] = 'cache_other'
                cache_other_ts = self._get_timeseries(cache_other_key_dict,
                                                      create=True)
                cache_other_ts.sum(ts)
                agg_tses.add(cache_other_ts)
                continue

            try:
                status_code = int(zone)
            except ValueError:
                continue
            if status_code < 100 or status_code >= 600:
                continue

            # Calculate total of all requests from the sum of all response code
            # requests timeseries.
            total_key_dict = dict(ts.key_dict)
            total_key_dict['zone'] = 'total'
            total_ts = self._get_timeseries(total_key_dict, create=True)
            total_ts.sum(ts)
            agg_tses.add(total_ts)

            status_code_zones.add(zone)
            if zone == '503':
                # Milliseconds does not count status code 503 into 5xx
                continue
            agg_zone = str(status_code // 100) + 'xx'
            status_code_zones.add(agg_zone)

            agg_key_dict = dict(ts.key_dict)
            agg_key_dict['zone'] = agg_zone
            agg_ts = self._get_timeseries(agg_key_dict, create=True)
            agg_ts.sum(ts)
            agg_tses.add(agg_ts)

        updated_ts.extend(agg_tses)
        return status_code_zones

    def _parse_zone(self, updated_ts: List[TimeSeries], t_cur: float,
                    backend: str, backend_stats: dict, zone: str):
        # Note: KeyError, IndexError and ValueError are catched at the caller
        # side.
        zone_backend_stats = backend_stats['serverZones'][zone]
        buckets = zone_backend_stats['requestBuckets']
        if len(buckets['msecs']) != len(buckets['counters']):
            raise ValueError('Bucket size mismatch')

        # Histogram for response duration
        for msecs, counter_value in zip(buckets['msecs'], buckets['counters']):
            # Store result in SI units (seconds).
            key = self._key_dict('response_duration', backend, zone,
                                 (HISTOGRAM_ATTR, msecs / 1000), UNIT_SECONDS)
            self._create_data_point(updated_ts, key, counter_value, t_cur)

        # Sum of response durations. Store result in SI units (seconds).
        self._create_data_point(
            updated_ts,
            self._key_dict('response_duration_sum', backend, zone,
                           UNIT_SECONDS),
            zone_backend_stats['requestMsecCounter'] / 1000, t_cur)

        # Request bytes (data to server)
        self._create_data_point(
            updated_ts,
            self._key_dict('bytes', backend, zone, ('direction', 'in'),
                           UNIT_BYTES),
            zone_backend_stats['inBytes'], t_cur)
        # Response bytes (data to clients)
        self._create_data_point(
            updated_ts,
            self._key_dict('bytes', backend, zone, ('direction', 'out'),
                           UNIT_BYTES),
            zone_backend_stats['outBytes'], t_cur)

        # Total number of requests in
        self._create_data_point(
            updated_ts,
            self._key_dict('requests_total', backend, zone, UNIT_REQUESTS),
            zone_backend_stats['requestCounter'], t_cur)


def _get_start_time(timet: float, interval: int) -> int:
    """Returns next time_t divisible by interval"""
    timet = round(timet)
    while True:
        if (timet % interval) == 0:
            return timet
        timet += 1
    assert False


def _plot(args, state):
    plot_zones = set()
    if len(args.plot_zones) > 0:
        for zone in args.plot_zones.split(','):
            plot_zones.add(zone.strip())

    histogram_plots = []
    bytes_plots = []
    requests_plots = []

    for (plot_type, key_tuple), values_list in (
            state._plots.items()):
        zone = parse_from_key_tuple(key_tuple, 'zone')
        if len(plot_zones) > 0 and zone not in plot_zones:
            continue

        filtered_key_tuple_l = []
        for attr, value in key_tuple:
            if attr not in ('backend', 'unit'):
                filtered_key_tuple_l.append((attr, value))
        filtered_key_tuple = tuple(sorted(filtered_key_tuple_l))

        if plot_type == 'histogram':
            for p in state._latency_percentiles:
                values = []
                times = []
                min_t = None
                for t, percentile_values in values_list:
                    if min_t is None:
                        min_t = t
                    if (percentile_values is not None and
                            p in percentile_values):
                        values.append(percentile_values[p] / 0.001)
                        times.append(t - min_t)
                histogram_plots.append(
                    (times, values,
                     'p:' + str(p) + ':' + str(filtered_key_tuple)))
        else:
            min_t = None
            values = []
            times = []
            for t, value in values_list:
                if min_t is None:
                    min_t = t
                values.append(value)
                times.append(t - min_t)
            if plot_type == 'bytes':
                target_plots = bytes_plots
            else:
                target_plots = requests_plots
            target_plots.append((times, values,
                                 'rate:' + str(filtered_key_tuple)))

    import matplotlib.pyplot as plt
    plt.figure()

    ax = plt.subplot(131)
    ax.set_xlabel('t (seconds)')
    ax.set_ylabel('latency (milliseconds)')
    plt.yscale('log')
    plt.grid(True)
    for times, values, label in histogram_plots:
        plt.plot(times, values, label=label)
    plt.legend()

    ax = plt.subplot(132)
    ax.set_xlabel('t (seconds)')
    ax.set_ylabel('bytes/s')
    plt.yscale('linear')
    plt.grid(True)
    for times, values, label in bytes_plots:
        plt.plot(times, values, label=label)
    plt.legend()
    ax.set_ybound(0.0, None)

    ax = plt.subplot(133)
    ax.set_xlabel('t (seconds)')
    ax.set_ylabel('requests/s')
    plt.yscale('linear')
    plt.grid(True)
    for times, values, label in requests_plots:
        plt.plot(times, values, label=label)
    plt.legend()
    ax.set_ybound(0.0, None)

    # Maximize the window
    mng = plt.get_current_fig_manager()
    mng.resize(*mng.window.maxsize())

    plt.show()


def _log_stats(stat_dir, backend_data, step):
    if stat_dir is None:
        return

    for backend, data in backend_data:
        split_result = urllib.parse.urlsplit(backend)
        if len(split_result.netloc) == 0:
            host = 'nohostname'
        else:
            host = split_result.netloc.split(':')[0]
        dest_name = os.path.join(stat_dir, '{}-{:06d}.json'.format(host, step))
        try:
            with open(dest_name, 'wb') as f:
                f.write(data)
        except OSError as e:
            log_error('Unable to write to stats dir', e)


def run_vtsaggregator(args):
    if args.interval <= 0:
        raise ConfigError('--interval value must be a positive integer')
    late_margin = args.late_margin
    if late_margin is None:
        late_margin = min(10.0, args.interval / 2)
    if late_margin <= 0 or late_margin > (args.interval / 2):
        raise ConfigError('--late-margin value must be a positive float '
                          'not greater than interval/2')
    state = State(args)
    state.load()

    t = time.time()
    if args.test_mode:
        t_next = t + args.interval
    else:
        t_next = _get_start_time(t, args.interval)

    CLOCK_DRIFT_MARGIN = 0.1

    step = 0
    while args.test_limit < 0 or step < args.test_limit:
        t = time.time()

        if args.test_mode:
            # No sleeping in test mode
            t = t_next

        if t < t_next:
            time.sleep(t_next + CLOCK_DRIFT_MARGIN - t)
            continue

        t_deadline = t_next + late_margin
        if t < t_deadline:
            if args.test_mode:
                if step >= len(args.urls):
                    print('No more test data. Stopping.')
                    break
                urls = [args.urls[step]]
            else:
                urls = args.urls

            # Fetch backend data from monitoring end-points
            backend_data = state.fetch_backend_data(urls, args)
            t_end = time.time()
            if t_end >= t_deadline:
                log_warning('Scraping was late by {} seconds. '
                            'Results are not counted.'.format(
                                t_end - t_deadline))

            _log_stats(args.stat_dir, backend_data, step)

            # Aggregate backend data
            state.aggregate_backend_data(t, backend_data, args)
            state.save()
            if args.verbose:
                t_analysis_end = time.time()
                print('Fetch_backend_data() duration: {:.3f}s'.format(
                    t_end - t))
                print('Aggregate and save duration: {:.3f}s'.format(
                    t_analysis_end - t_end))
        else:
            log_warning('Missed a minute interval: time_t', t)
        t_next += args.interval
        step += 1

    if args.plot:
        _plot(args, state)


def main():
    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        'urls', metavar='URL', nargs='+',
        help=('A URL or a file. A URL should point to an nginx vhost traffic '
              'status end-point that provides monitoring metrics as JSON. '
              'The URL should end with \'/format/json\'. '
              'Example: https://host/prefix/format/json. '
              'A file path can be provided instead of a URL when testing.'))
    parser.add_argument(
        '--checkpoint', required=True,
        help=('Checkpoint file to save backend metrics. '
              'This is a mandatory argument.'))
    parser.add_argument(
        '--insecure', action='store_true',
        help='Do not validate HTTPS certificate.')
    parser.add_argument(
        '--interval', type=int, default=60,
        help='Scraping interval in seconds')
    parser.add_argument(
        '--late-margin', type=float,
        help=('Determine how many seconds after interval start all '
              'processing must be finished. By default this is '
              'min(10.0, interval / 2).'))
    parser.add_argument(
        '--latency-percentiles', default='0,1,5,10,50,90,95,99,100',
        help='Comma separated floats of latency percentiles to monitor for.')
    parser.add_argument(
        '--log-dir',
        help=('Write logs of errors and exceptional at '
              '{log_dir}/vtsaggregator.log where log_dir is the given '
              'argument.'))
    parser.add_argument(
        '--milliseconds', required=True,
        help=('Write millisecond json to a given target file. The target '
              'file is updated atomically so that it can be served as a '
              'static file safely. The process of creation is as follows: '
              '0. Create a temp file in the same directory as '
              'the target file. 1. Atomically rename the temp file as the '
              'target file. '
              'This is a mandatory argument.'))
    parser.add_argument(
        '--plot', action='store_true',
        help=('Plot statistics with matplotlib. Useful for testing. '
              'matplotlib is not required for normal operation.'))
    parser.add_argument(
        '--plot-zones', default='',
        help='Plot statistics for given zones separated with commas.')
    parser.add_argument(
        '--stat-dir',
        help=('Log json stats obtained from vts plugin to files named '
              '{dir}/{backend}-{.06d}.json where backend is the host name '
              'of the server where the vts plugin is run and dir is the '
              'given argument.'))
    parser.add_argument(
        '--test-limit', type=int, default=-1,
        help='Evaluate monitoring given number of intervals and then stop')
    parser.add_argument(
        '--test-mode', action='store_true',
        help='No sleeping. Given URLs are a sequence of json dumps.')
    parser.add_argument(
        '--timeout', type=float, default=2.0,
        help='Timeout for fetching statistics from backends.')
    parser.add_argument(
        '--verbose', action='store_true',
        help='Print verbose stats on stdout.')
    parser.add_argument(
        '--verbose-zones',
        help='Print given comma separated zones in verbose mode.')
    parser.add_argument(
        '--version', action='version', version='%(prog)s {}'.format(VERSION))
    parser.add_argument(
        '--zones', default='',
        help=('Comma separated string list of monitoring zones, e.g. '
              'MISS for cache miss statistics. '
              'Defaults to monitoring all zones.'))
    args = parser.parse_args()

    global LOG_DIR
    LOG_DIR = args.log_dir

    try:
        run_vtsaggregator(args)
    except Exception as e:
        log_exception(e, 'Exception not catched')
    return 0


if __name__ == '__main__':
    sys.exit(main())

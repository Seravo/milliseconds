# A simple type validator to check types of bencoded data that comes from
# an untrusted source (say, network).
#
# SPDX-License-Identifier: BSD-2-Clause
# See LICENSE.typevalidator for more information.
#
# Originally written by Heikki Orsila <heikki.orsila@iki.fi> on 2009-09-12
#
# Repository at https://gitlab.com/heikkiorsila/bencodetools

from types import FunctionType

# BOOL*, INT*, STRING* and FLOAT* are used for backward compability
# with the old interface. New code should use bool/int/str/float directly.
BOOL = bool
BOOL_KEY = bool
INT = int
INT_KEY = int
STRING = str
STRING_KEY = str
FLOAT = float
FLOAT_KEY = float


class ANY:
    pass


class ZERO_OR_MORE:
    pass


class ONE_OR_MORE:
    pass


class OPTIONAL_KEY:
    def __init__(self, key):
        if type(key) == type:
            raise ValueError('key {} must not be a type'.format(key))
        self.key = key


class ValidationError(ValueError):
    def __init__(self, reason='', fmt=None, obj=None):
        self._reason = reason
        self.fmt = fmt
        self.obj = obj

    def __str__(self):
        return self._reason


# Define Invalid_Format_Object for backwards compatibility
Invalid_Format_Object = ValidationError


class Context:
    def __init__(self, raise_error=False):
        self._stack = []
        self._raise_error = raise_error

    def error(self, fmt, obj):
        if self._raise_error:
            raise ValidationError(
                reason=('Validation error: {} expected format is '
                        '{} and value is {}'.format(
                            self._print_stack(), repr(fmt), repr(obj))),
                fmt=fmt, obj=obj)

    def error2(self, msg, fmt, obj):
        if self._raise_error:
            raise ValidationError(
                reason=('Validation error: {} {}'.format(
                    self._print_stack(), msg)),
                fmt=fmt, obj=obj)

    def _print_stack(self):
        if len(self._stack) == 0:
            return 'At root position'
        return 'At position ' + ''.join(self._stack)

    def pop(self):
        self._stack.pop()

    def push(self, s):
        self._stack.append(s)

    def is_root(self):
        return len(self._stack) == 0


# Example:
# SPEC = {'value': one_of(['x', 'y'])}
# then validate(SPEC, d) means that d['value'] must be either 'x' or 'y'
def one_of(alternatives):
    d = {}
    for alternative in alternatives:
        d[alternative] = alternative

    def test_f(o):
        return o in d and isinstance(o, type(d[o]))

    return test_f


def _validate_list(org_fmt, org_o, ctx):
    if type(org_o) != list:
        ctx.error2('expect a list. Class is {}'.format(type(org_o)),
                   list, org_o)
        return False

    if ctx.is_root():
        ctx.push('[]')

    fmt = list(org_fmt)
    o = list(org_o)
    pos = 0
    while len(fmt) > 0:
        fitem = fmt.pop(0)
        if fitem == ZERO_OR_MORE or fitem == ONE_OR_MORE:
            if len(fmt) == 0:
                raise ValidationError(
                    'In list fmt {}: missing list element type'.format(
                        org_fmt))
            ftype = fmt.pop(0)
            if len(o) == 0:
                if fitem == ONE_OR_MORE:
                    ctx.error2('expect a value in list, but there is none.',
                               fmt=org_fmt, obj=org_o)
                    return False
                continue

            while len(o) > 0:
                ctx.push('[{}]'.format(pos))
                if not _validate(ftype, o[0], ctx):
                    # This is somewhat esoteric. It is possible to concatenate
                    # list segments of different types.
                    # E.g. [ONE_OR_MORE, int, ZERO_OR_MORE, str].
                    if len(fmt) > 0:
                        break
                    return False
                ctx.pop()
                o.pop(0)
                pos += 1
            continue
        if len(o) == 0:
            ctx.error2('expect a value in list, but there is none.',
                       fmt=org_fmt, obj=org_o)
            return False
        oitem = o.pop(0)
        ctx.push('[{}]'.format(pos))
        if not _validate(fitem, oitem, ctx):
            return False
        ctx.pop()
        pos += 1

    ret = (len(o) == 0)
    if not ret:
        ctx.error(org_fmt, org_o)

    if ctx.is_root():
        ctx.pop('[]')

    return ret


def _validate_dict(fmt, o, ctx):
    if type(o) != dict:
        ctx.error2('expect a dict. Class is {}'.format(type(o)), dict, o)
        return False

    if ctx.is_root():
        ctx.push('{}')

    for key in fmt.keys():
        key_is_type = (type(key) == type)
        if isinstance(key, OPTIONAL_KEY):
            # OPTIONAL_KEY
            if key.key in o:
                ctx.push('[{}]'.format(repr(key.key)))
                if not _validate(fmt[key], o[key.key], ctx):
                    return False
                ctx.pop()
        elif key_is_type:
            # str, int, ...
            for okey in o.keys():
                if key is not ANY:
                    if type(okey) == type or type(okey) != key:
                        ctx.error2(
                            'expect key is in {} but key is {}'.format(
                                key, repr(okey)), key, okey)
                        return False
                ctx.push('[{}]'.format(repr(okey)))
                if not _validate(fmt[key], o[okey], ctx):
                    return False
                ctx.pop()
        else:
            # Key is a value, not a type. It must exist in the object.
            if key not in o:
                ctx.error2('key {} does not exist'.format(repr(key)), fmt, o)
                return False
            ctx.push('[{}]'.format(repr(key)))
            if not _validate(fmt[key], o[key], ctx):
                return False
            ctx.pop()

    if ctx.is_root():
        ctx.pop()

    return True


def _validate(fmt, o, ctx):
    if fmt == ANY:
        return True

    # Is this a user defined checker function?
    if type(fmt) == FunctionType:
        ret = fmt(o)
        if not ret:
            ctx.error2('function call {}({}) returns False'.format(
                fmt.__name__, repr(o)), fmt, o)
        return ret
    elif type(fmt) == list:
        return _validate_list(fmt, o, ctx)
    elif type(fmt) == dict:
        return _validate_dict(fmt, o, ctx)
    elif type(fmt) == type:
        if fmt != type(o) and fmt is not ANY:
            ctx.error2('expect type {} and value is {}'.format(
                fmt.__name__, repr(o)), fmt, o)
            return False
    # If given format is a not a type but a value, compare input to the given
    # value
    elif fmt != o:
        ctx.error2('expect value {}, but value is {}'.format(
            repr(fmt), repr(o)), fmt, o)
        return False

    return True


def validate(fmt, o):
    """Returns True if o is valid with respect to fmt, False otherwise."""
    ctx = Context()
    return _validate(fmt, o, ctx)


def validate2(fmt, o):
    """Similar to validate() but raises ValidationError() if o is not valid.

    ValidationError is a subclass of ValueError.
    Catching ValidationError rather than ValueError allows to gain insight
    where the validation failed inside o.
    """
    ctx = Context(raise_error=True)
    return _validate(fmt, o, ctx)


def test_validate():
    assert validate(
        [str, [ONE_OR_MORE, int], [ZERO_OR_MORE, int], {'a': int, 1: str}],
        ['fff', [0], [], {'a': 0, 1: 'foo'}])
    assert validate(
        [str, [ONE_OR_MORE, int], [ZERO_OR_MORE, int], {'a': int, 1: str}],
        [1, [0], [], {'a': 0, 1: 'foo'}]) is False
    assert validate(
        [str, [ONE_OR_MORE, int], [ZERO_OR_MORE, int], {'a': int, 1: str}],
        ['fff', [], [], {'a': 0, 1: 'foo'}]) is False
    assert validate([ONE_OR_MORE, int, ZERO_OR_MORE, str], [1, 1, 1])
    assert validate([ONE_OR_MORE, int, ZERO_OR_MORE, str], [1, 1, 1, 's'])
    assert validate([ZERO_OR_MORE, int, ONE_OR_MORE, str], [1, 1, 1, 's'])
    assert validate([ZERO_OR_MORE, int, ONE_OR_MORE, str], [1, 1, 1]) is False
    assert validate([ZERO_OR_MORE, int, ONE_OR_MORE, str], ['d'])
    assert validate([ZERO_OR_MORE, int, ONE_OR_MORE, str], []) is False

    assert(validate(lambda x: x % 2 == 0, 0))
    assert(validate(lambda x: x % 2 == 0, 1) is False)

    assert(validate({str: str}, {'a': 'b'}))
    assert(validate({str: str}, {1: 'b'}) is False)
    assert(validate({str: str}, {'a': 1}) is False)
    assert(validate({str: int}, {'a': 1}))
    assert(validate({int: str}, {1: 'a'}))
    assert(validate({int: str}, {1: 'a', 'b': 2}) is False)

    # Extra keys in dictionary are allowed
    assert(validate({'x': int}, {'x': 1, 'y': 1}))
    # Missing key fails
    assert(validate({'x': int}, {'y': 1}) is False)

    # OK
    assert(validate({'x': int, str: int}, {'x': 1, 'y': 1}))
    # Non-string key
    assert(validate({'x': int, str: int}, {'x': 1, 1: 1}) is False)
    # Missing key, but correct key type
    assert(validate({'x': int, str: int}, {'y': 1}) is False)

    assert(validate({'x': bool}, {'x': False}))
    assert(validate({'x': bool}, {'x': 0}) is False)

    # Test OPTIONAL_KEY
    assert(validate({OPTIONAL_KEY('x'): int}, {}))
    assert(validate({OPTIONAL_KEY('x'): int}, {'x': 1}))
    assert(validate({OPTIONAL_KEY('x'): int}, {'x': 'invalid'}) is False)

    # Typevalidator can be used to check that values are equal
    assert(validate([1, 2, 3, [True, 'a']], [1, 2, 3, [True, 'a']]))
    assert(validate('foo', 'bar') is False)

    assert(validate(float, 0.0))
    assert(validate(float, 1) is False)

    assert(validate({'value': one_of(['x', 'y'])}, {'value': 'x'}))
    assert(validate({'value': one_of(['x', 'y'])}, {'value': 'z'}) is False)

    # Test ANY as dict key
    assert(validate({ANY: int}, {'1': 1, 2: 2}))
    assert(validate({ANY: int}, {str: 1}))
    assert(validate({str: ANY}, {'1': ANY}))
    assert(validate({ANY: ANY}, {ANY: ANY}))

    # Test ANY as list type
    assert(validate([ZERO_OR_MORE, ANY], []))
    assert(validate([ZERO_OR_MORE, ANY], [1]))
    assert(validate([ZERO_OR_MORE, ANY], [1, '2']))
    assert(validate([ZERO_OR_MORE, ANY], [1, '2', ANY]))

    assert validate({str: int}, {str: 1}) is False
    assert validate({str: int}, {'x': int}) is False

    try:
        validate({OPTIONAL_KEY(str): str}, {'1': '2'})
        assert False
    except ValueError:
        pass

    # Test validation exceptions
    assert validate2(int, 1)
    try:
        validate2(int, '1')
        assert False
    except ValueError:
        pass
    try:
        validate2([ZERO_OR_MORE, int], ['x'])
        assert False
    except ValueError:
        pass
    try:
        validate2(['x'], [1])
        assert False
    except ValueError:
        pass
    try:
        validate2(['x'], 's')
        assert False
    except ValueError:
        pass
    try:
        validate2({'x': int}, {'x': 'y'})
        assert False
    except ValueError:
        pass
    try:
        validate2({str: int}, {1: 'y'})
        assert False
    except ValueError:
        pass
    try:
        validate2([], 'x')
        assert False
    except ValueError:
        pass
    try:
        validate2(['x'], [])
        assert False
    except ValueError:
        pass
    try:
        validate2({}, [])
        assert False
    except ValueError:
        pass
    try:
        validate2({'x': int}, {})
        assert False
    except ValueError:
        pass
    try:
        validate2(lambda x: (x & 1) == 0, 1)
        assert False
    except ValueError:
        pass

    try:
        validate2({'x': [ZERO_OR_MORE, str]}, {'x': ['y', 0]})
        assert False
    except ValueError:
        pass
    assert validate({'x': [ZERO_OR_MORE, {'y': dict}]}, {'x': []})
    assert validate({'x': [ZERO_OR_MORE, {'y': dict}]}, {'x': [{'y': {}}]})

    assert not validate({'x': [ONE_OR_MORE, {'y': dict}]}, {'x': []})


if __name__ == '__main__':
    test_validate()

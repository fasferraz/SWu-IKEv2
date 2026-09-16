import argparse
import socket

try:
    import yaml
except ImportError:
    yaml = None

import ikev2_const
from ikev2_const import (
    D_H,
    KEY_LENGTH,
    REPEAT_STATE,
    REPEAT_STATE_COOKIE,
    notify_name,
)

# YAML keys match CLI long options (underscores instead of dashes).
CONFIG_TO_ATTR = {
    'modem': 'modem',
    'source': 'source_addr',
    'dest': 'destination_addr',
    'apn': 'apn',
    'gateway_ip_address': 'gateway_ip_address',
    'imsi': 'imsi',
    'mcc': 'mcc',
    'mnc': 'mnc',
    'ki': 'ki',
    'op': 'op',
    'opc': 'opc',
    'netns': 'netns',
    'sqn': 'sqn',
    'no_default_route': 'no_default_route',
    'no_dns': 'no_dns',
    'export_keys': 'export_keys',
    'headless': 'headless',
    'imei': 'imei',
    'imeisv': 'imeisv',
    'log_level': 'log_level',
    'dpd': 'dpd',
    'keepalive': 'keepalive',
    'reconnect': 'reconnect',
}

PROPOSAL_KEYS = frozenset((
    'ike_sa', 'child_sa', 'ts_initiator', 'ts_responder', 'cp',
))

BOOL_KEYS = frozenset(('no_default_route', 'no_dns', 'headless'))
INT_KEYS = frozenset(('dpd', 'keepalive', 'reconnect'))
DEFAULT_KEEPALIVE_SECONDS = 20
QUOTED_STRING_KEYS = frozenset((
    'imsi', 'ki', 'op', 'opc', 'imei', 'imeisv', 'sqn', 'mcc', 'mnc',
))
DEFAULT_DPD_SECONDS = 30


def _const(name, where):
    if not isinstance(name, str):
        raise ValueError(where + ' must be a constant name, got ' + repr(name))
    if name.startswith('_') or not hasattr(ikev2_const, name):
        raise ValueError(where + ': unknown name ' + name)
    value = getattr(ikev2_const, name)
    if not isinstance(value, int):
        raise ValueError(where + ': ' + name + ' is not an integer constant')
    return value


def _reject_unknown(mapping, allowed, where):
    extra = sorted(set(mapping) - allowed)
    if extra:
        raise ValueError(where + ' unknown keys: ' + ', '.join(extra))


def parse_sa_list(value, where):
    if not isinstance(value, list) or not value:
        raise ValueError(where + ' must be a non-empty list of proposals')
    out = []
    for index, proposal in enumerate(value):
        loc = where + '[' + str(index) + ']'
        if not isinstance(proposal, dict):
            raise ValueError(loc + ' must be a mapping')
        _reject_unknown(proposal, frozenset(('protocol', 'spi_size', 'transforms')), loc)
        if 'protocol' not in proposal or 'spi_size' not in proposal or 'transforms' not in proposal:
            raise ValueError(loc + ' needs protocol, spi_size, and transforms')
        if not isinstance(proposal['spi_size'], int):
            raise ValueError(loc + '.spi_size must be an integer')
        transforms = proposal['transforms']
        if not isinstance(transforms, list) or not transforms:
            raise ValueError(loc + '.transforms must be a non-empty list')
        row = [[_const(proposal['protocol'], loc + '.protocol'), proposal['spi_size']]]
        for t_index, transform in enumerate(transforms):
            tloc = loc + '.transforms[' + str(t_index) + ']'
            if not isinstance(transform, dict):
                raise ValueError(tloc + ' must be a mapping')
            _reject_unknown(transform, frozenset(('type', 'id', 'key_length')), tloc)
            if 'type' not in transform or 'id' not in transform:
                raise ValueError(tloc + ' needs type and id')
            item = [
                _const(transform['type'], tloc + '.type'),
                _const(transform['id'], tloc + '.id'),
            ]
            if 'key_length' in transform:
                if not isinstance(transform['key_length'], int):
                    raise ValueError(tloc + '.key_length must be an integer')
                item.append([KEY_LENGTH, transform['key_length']])
            row.append(item)
        out.append(row)
    return out


def parse_ts_list(value, where):
    if not isinstance(value, list) or not value:
        raise ValueError(where + ' must be a non-empty list')
    out = []
    allowed = frozenset(('type', 'protocol', 'start_port', 'end_port', 'start', 'end'))
    for index, selector in enumerate(value):
        loc = where + '[' + str(index) + ']'
        if not isinstance(selector, dict):
            raise ValueError(loc + ' must be a mapping')
        _reject_unknown(selector, allowed, loc)
        missing = allowed - set(selector)
        if missing:
            raise ValueError(loc + ' missing ' + ', '.join(sorted(missing)))
        if not isinstance(selector['start_port'], int) or not isinstance(selector['end_port'], int):
            raise ValueError(loc + ' ports must be integers')
        if not isinstance(selector['start'], str) or not isinstance(selector['end'], str):
            raise ValueError(loc + ' start and end must be address strings')
        out.append([
            _const(selector['type'], loc + '.type'),
            _const(selector['protocol'], loc + '.protocol'),
            selector['start_port'],
            selector['end_port'],
            selector['start'],
            selector['end'],
        ])
    return out


def parse_cp(value, where):
    if not isinstance(value, dict):
        raise ValueError(where + ' must be a mapping')
    _reject_unknown(value, frozenset(('type', 'attributes')), where)
    if 'type' not in value or 'attributes' not in value:
        raise ValueError(where + ' needs type and attributes')
    attributes = value['attributes']
    if not isinstance(attributes, list) or not attributes:
        raise ValueError(where + '.attributes must be a non-empty list')
    out = [_const(value['type'], where + '.type')]
    for index, attribute in enumerate(attributes):
        loc = where + '.attributes[' + str(index) + ']'
        if isinstance(attribute, str):
            out.append([_const(attribute, loc)])
            continue
        if not isinstance(attribute, dict):
            raise ValueError(loc + ' must be a name or a mapping')
        _reject_unknown(attribute, frozenset(('type', 'value')), loc)
        if 'type' not in attribute:
            raise ValueError(loc + ' needs type')
        item = [_const(attribute['type'], loc + '.type')]
        if 'value' in attribute:
            if not isinstance(attribute['value'], str):
                raise ValueError(loc + '.value must be a string')
            item.append(attribute['value'])
        out.append(item)
    return out


def parse_proposals(raw):
    proposals = {}
    if 'ike_sa' in raw:
        proposals['ike_sa'] = parse_sa_list(raw['ike_sa'], 'ike_sa')
    if 'child_sa' in raw:
        proposals['child_sa'] = parse_sa_list(raw['child_sa'], 'child_sa')
    if 'ts_initiator' in raw:
        proposals['ts_initiator'] = parse_ts_list(raw['ts_initiator'], 'ts_initiator')
    if 'ts_responder' in raw:
        proposals['ts_responder'] = parse_ts_list(raw['ts_responder'], 'ts_responder')
    if 'cp' in raw:
        proposals['cp'] = parse_cp(raw['cp'], 'cp')
    return proposals


def _read_mapping(path):
    if yaml is None:
        raise ImportError('PyYAML is not installed. Re-run ./install_deps.sh')
    with open(path) as handle:
        data = yaml.safe_load(handle)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError('config file must be a YAML mapping')
    unknown = sorted(set(data) - set(CONFIG_TO_ATTR) - PROPOSAL_KEYS)
    if unknown:
        raise ValueError('unknown config keys: ' + ', '.join(unknown))
    return data


def _normalize_options(raw):
    data = {}
    for key, value in raw.items():
        if key not in CONFIG_TO_ATTR:
            continue
        if key in BOOL_KEYS:
            if not isinstance(value, bool):
                raise ValueError(key + ' must be true or false')
        elif key in INT_KEYS:
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(key + ' must be an integer >= 0')
        elif key in QUOTED_STRING_KEYS and value is not None and not isinstance(value, str):
            raise ValueError(key + ' must be a quoted string so leading zeros are kept')
        elif value is not None and not isinstance(value, (str, bool)):
            value = str(value)
        data[key] = value
    return data


def load_config(path):
    return _normalize_options(_read_mapping(path))


def apply_config(values, defaults, config):
    """Fill values from config where the current value is still the parser default."""
    out = dict(values)
    for yaml_key, attr in CONFIG_TO_ATTR.items():
        if yaml_key not in config:
            continue
        if out.get(attr) == defaults.get(attr):
            out[attr] = config[yaml_key]
    return out


def apply_file_config(options, defaults, path):
    raw = _read_mapping(path)
    merged = apply_config(vars(options), defaults, _normalize_options(raw))
    for attr, value in merged.items():
        setattr(options, attr, value)
    return parse_proposals(raw)


LOG_LEVELS = frozenset(('debug', 'info', 'warning', 'error'))


def argparse_defaults(parser):
    return {
        action.dest: action.default
        for action in parser._actions
        if action.dest not in (None, 'help', argparse.SUPPRESS)
    }


def normalize_log_level(value):
    if value is None:
        return 'info'
    name = str(value).lower()
    if name not in LOG_LEVELS:
        raise ValueError('--log-level must be debug, info, warning, or error')
    return name


def resolve_reconnect_attempts(configured):
    if configured is None:
        return 0
    value = int(configured)
    if value < 0:
        raise ValueError('--reconnect must be >= 0')
    return value


def resolve_keepalive_seconds(configured):
    if configured is None:
        return DEFAULT_KEEPALIVE_SECONDS
    value = int(configured)
    if value < 0:
        raise ValueError('--keepalive must be >= 0')
    return value


def resolve_dpd_seconds(configured, cp_seconds):
    """CLI/YAML wins. 0 disables. Else CP TIMEOUT_PERIOD, else 30."""
    if configured is not None:
        value = int(configured)
        if value < 0:
            raise ValueError('--dpd must be >= 0')
        return value
    if cp_seconds is not None:
        value = int(cp_seconds)
        if value < 0:
            raise ValueError('TIMEOUT_PERIOD_FOR_LIVENESS_CHECK must be >= 0')
        return value
    return DEFAULT_DPD_SECONDS


def format_ike_event(result, info):
    kind = 'retry' if result in (REPEAT_STATE, REPEAT_STATE_COOKIE) else 'failed'
    text = '' if info is None else str(info).strip()
    if text.isdigit():
        code = int(text)
        return 'event=%s notify=%s code=%s' % (kind, notify_name(code), code)
    label = text.replace(' ', '_') or '-'
    if label in ikev2_const.NOTIFY_NAMES.values():
        return 'event=%s notify=%s' % (kind, label)
    return 'event=%s reason=%s' % (kind, label)


def format_ipv6_host(addr):
    return socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, addr))


def format_connected_event(apn, dest, ipv4, ipv6):
    def join(items):
        if not items:
            return '-'
        return ','.join(str(item) for item in items)

    return 'event=connected apn=%s dest=%s ipv4=%s ipv6=%s' % (
        apn or '-',
        dest or '-',
        join(ipv4),
        join(ipv6),
    )


def validate_device_identity(imei, imeisv):
    if imei is not None and (len(imei) != 15 or not imei.isdigit()):
        raise ValueError('--imei must be 15 digits')
    if imeisv is not None and (len(imeisv) != 16 or not imeisv.isdigit()):
        raise ValueError('--imeisv must be 16 digits')
    return imei, imeisv


def validate_aka_credentials(imsi, ki, op, opc):
    """Software AKA: Ki needs OP or OPc. IMSI can come later from a reader."""
    if ki is None:
        return
    if op is None and opc is None:
        raise ValueError('--ki requires --op or --opc')


def filter_ike_sa_by_dh(sa_list, dh_group):
    """Keep IKE proposals whose DH transform matches dh_group."""
    matched = []
    for proposal in sa_list or []:
        for item in proposal:
            if item[0] == D_H and item[1] == dh_group:
                matched.append(proposal)
                break
    return matched

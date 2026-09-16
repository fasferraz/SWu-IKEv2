import argparse
import importlib.util
import os
import tempfile
import unittest
from types import SimpleNamespace

from ikev2_const import (
    ANY,
    AUTHENTICATION_FAILED,
    AUTH_HMAC_SHA1_96,
    AUTH_HMAC_SHA2_256_128,
    CFG_REQUEST,
    D_H,
    EAP_AKA,
    EAP_IDENTITY,
    EAP_REQUEST,
    EAP_RESPONSE,
    ENCR,
    ENCR_AES_CBC,
    ENCR_AES_GCM_8,
    ENCR_DES,
    ENCR_NULL,
    ECP_256_bit,
    ECP_384_bit,
    ECP_521_bit,
    IKE,
    INTEG,
    INTERNAL_IP4_ADDRESS,
    INTERNAL_IP6_ADDRESS,
    INTERNAL_IP6_DNS,
    P_CSCF_IP6_ADDRESS,
    KEY_LENGTH,
    MODP_1024_bit,
    MODP_2048_bit,
    MODP_768_bit,
    NO_APN_SUBSCRIPTION,
    NO_PROPOSAL_CHOSEN,
    OTHER_ERROR,
    PRF,
    PRF_HMAC_SHA1,
    REPEAT_STATE,
    TIMEOUT_PERIOD_FOR_LIVENESS_CHECK,
    TS_IPV4_ADDR_RANGE,
    TS_IPV6_ADDR_RANGE,
    USER_UNKNOWN,
    eap_identity_reply,
    eap_permanent_nai,
    encode_eap_identity_response,
    is_eap_identity_request,
    notify_name,
)
from swu_config import (
    apply_config,
    apply_file_config,
    argparse_defaults,
    format_connected_event,
    format_ike_event,
    filter_ike_sa_by_dh,
    format_ipv6_host,
    load_config,
    normalize_log_level,
    parse_proposals,
    resolve_dpd_seconds,
    resolve_keepalive_seconds,
    resolve_reconnect_attempts,
    validate_aka_credentials,
    validate_device_identity,
)


@unittest.skipIf(importlib.util.find_spec('yaml') is None, 'PyYAML is not installed')
class LoadConfig(unittest.TestCase):

    def _write(self, text):
        handle = tempfile.NamedTemporaryFile('w', suffix='.yaml', delete=False)
        try:
            handle.write(text)
            handle.close()
            return handle.name
        except Exception:
            os.unlink(handle.name)
            raise

    def tearDown(self):
        path = getattr(self, '_path', None)
        if path and os.path.exists(path):
            os.unlink(path)

    def test_quoted_subscriber_fields(self):
        self._path = self._write(
            'imsi: "001011234567890"\n'
            'ki: "000102030405060708090a0b0c0d0e0f"\n'
            'headless: true\n'
        )
        data = load_config(self._path)
        self.assertEqual(data['imsi'], '001011234567890')
        self.assertEqual(data['ki'], '000102030405060708090a0b0c0d0e0f')
        self.assertTrue(data['headless'])

    def test_unquoted_imsi_is_rejected(self):
        self._path = self._write('imsi: 1011234567890\n')
        with self.assertRaises(ValueError):
            load_config(self._path)

    def test_unknown_key_is_rejected(self):
        self._path = self._write('foo: bar\n')
        with self.assertRaises(ValueError):
            load_config(self._path)

    def test_dpd_is_integer(self):
        self._path = self._write('dpd: 45\n')
        self.assertEqual(load_config(self._path)['dpd'], 45)
        os.unlink(self._path)
        self._path = self._write('dpd: -1\n')
        with self.assertRaises(ValueError):
            load_config(self._path)

    def test_keepalive_and_reconnect_are_integers(self):
        self._path = self._write('keepalive: 15\nreconnect: 3\n')
        data = load_config(self._path)
        self.assertEqual(data['keepalive'], 15)
        self.assertEqual(data['reconnect'], 3)
        os.unlink(self._path)
        self._path = self._write('keepalive: -1\n')
        with self.assertRaises(ValueError):
            load_config(self._path)


class ApplyConfig(unittest.TestCase):

    def test_yaml_fills_defaults_cli_wins(self):
        defaults = {'imsi': None, 'headless': False, 'destination_addr': '1.2.3.4'}
        values = dict(defaults)
        values['destination_addr'] = '9.9.9.9'
        merged = apply_config(
            values,
            defaults,
            {'imsi': '001011234567890', 'headless': True, 'dest': '192.168.64.1'},
        )
        self.assertEqual(merged['imsi'], '001011234567890')
        self.assertTrue(merged['headless'])
        self.assertEqual(merged['destination_addr'], '9.9.9.9')


class Proposals(unittest.TestCase):

    def test_parse_ike_ts_cp(self):
        parsed = parse_proposals({
            'ike_sa': [{
                'protocol': 'IKE',
                'spi_size': 0,
                'transforms': [
                    {'type': 'ENCR', 'id': 'ENCR_NULL'},
                    {'type': 'PRF', 'id': 'PRF_HMAC_SHA1'},
                    {'type': 'INTEG', 'id': 'AUTH_HMAC_SHA1_96'},
                    {'type': 'D_H', 'id': 'MODP_1024_bit'},
                ],
            }],
            'ts_initiator': [{
                'type': 'TS_IPV4_ADDR_RANGE',
                'protocol': 'ANY',
                'start_port': 0,
                'end_port': 65535,
                'start': '0.0.0.0',
                'end': '255.255.255.255',
            }],
            'cp': {
                'type': 'CFG_REQUEST',
                'attributes': ['INTERNAL_IP4_ADDRESS'],
            },
        })
        self.assertEqual(parsed['ike_sa'], [[
            [IKE, 0],
            [ENCR, ENCR_NULL],
            [PRF, PRF_HMAC_SHA1],
            [INTEG, AUTH_HMAC_SHA1_96],
            [D_H, MODP_1024_bit],
        ]])
        self.assertEqual(
            parsed['ts_initiator'],
            [[TS_IPV4_ADDR_RANGE, ANY, 0, 65535, '0.0.0.0', '255.255.255.255']],
        )
        self.assertEqual(parsed['cp'], [CFG_REQUEST, [INTERNAL_IP4_ADDRESS]])

    def test_ecp_group_name(self):
        parsed = parse_proposals({
            'ike_sa': [{
                'protocol': 'IKE',
                'spi_size': 0,
                'transforms': [
                    {'type': 'ENCR', 'id': 'ENCR_AES_CBC', 'key_length': 128},
                    {'type': 'D_H', 'id': 'ECP_256_bit'},
                ],
            }],
        })
        self.assertEqual(parsed['ike_sa'][0][-1], [D_H, ECP_256_bit])

    def test_cp_liveness_attribute(self):
        parsed = parse_proposals({
            'cp': {
                'type': 'CFG_REQUEST',
                'attributes': ['INTERNAL_IP4_ADDRESS', 'TIMEOUT_PERIOD_FOR_LIVENESS_CHECK'],
            },
        })
        self.assertEqual(
            parsed['cp'],
            [CFG_REQUEST, [INTERNAL_IP4_ADDRESS], [TIMEOUT_PERIOD_FOR_LIVENESS_CHECK]],
        )

    def test_key_length_and_unknown_id(self):
        parsed = parse_proposals({
            'ike_sa': [{
                'protocol': 'IKE',
                'spi_size': 0,
                'transforms': [
                    {'type': 'ENCR', 'id': 'ENCR_AES_CBC', 'key_length': 128},
                ],
            }],
        })
        self.assertEqual(parsed['ike_sa'][0][1], [ENCR, ENCR_AES_CBC, [KEY_LENGTH, 128]])
        with self.assertRaises(ValueError):
            parse_proposals({
                'ike_sa': [{
                    'protocol': 'IKE',
                    'spi_size': 0,
                    'transforms': [{'type': 'ENCR', 'id': 'ENCR_NOPE'}],
                }],
            })


@unittest.skipIf(importlib.util.find_spec('yaml') is None, 'PyYAML is not installed')
class SwuYaml(unittest.TestCase):

    def test_sample_file_offers_full_proposals(self):
        options = SimpleNamespace(
            destination_addr='1.2.3.4',
            imsi=None,
            ki=None,
            opc=None,
            apn='internet',
            mcc=None,
            mnc=None,
            headless=False,
            no_default_route=False,
            no_dns=False,
        )
        proposals = apply_file_config(options, dict(vars(options)), 'swu.yaml')
        self.assertEqual(options.destination_addr, '192.168.64.1')
        self.assertEqual(options.imsi, '001011234567890')
        self.assertFalse(options.headless)
        self.assertTrue(options.no_default_route)
        self.assertTrue(options.no_dns)
        self.assertEqual(len(proposals['ike_sa']), 6)
        self.assertEqual(
            [proposal[-1] for proposal in proposals['ike_sa']],
            [
                [D_H, MODP_1024_bit],
                [D_H, MODP_2048_bit],
                [D_H, MODP_1024_bit],
                [D_H, ECP_256_bit],
                [D_H, ECP_384_bit],
                [D_H, ECP_521_bit],
            ],
        )
        self.assertEqual(len(proposals['child_sa']), 7)
        self.assertEqual(proposals['child_sa'][0][1], [ENCR, ENCR_AES_GCM_8, [KEY_LENGTH, 256]])
        self.assertEqual(proposals['child_sa'][1][2], [INTEG, AUTH_HMAC_SHA2_256_128])
        self.assertEqual(proposals['cp'][0], CFG_REQUEST)
        cp_attrs = [item[0] for item in proposals['cp'][1:]]
        self.assertEqual(
            cp_attrs,
            [
                INTERNAL_IP6_ADDRESS,
                INTERNAL_IP6_DNS,
                P_CSCF_IP6_ADDRESS,
                TIMEOUT_PERIOD_FOR_LIVENESS_CHECK,
            ],
        )
        self.assertEqual(len(proposals['ts_initiator']), 1)
        self.assertEqual(proposals['ts_initiator'][0][0], TS_IPV6_ADDR_RANGE)
        self.assertEqual(len(proposals['ts_responder']), 1)
        self.assertEqual(proposals['ts_responder'][0][0], TS_IPV6_ADDR_RANGE)


@unittest.skipIf(importlib.util.find_spec('yaml') is None, 'PyYAML is not installed')
class NegativeProfiles(unittest.TestCase):

    def _load(self, name):
        options = SimpleNamespace(
            destination_addr='1.2.3.4',
            imsi=None,
            ki=None,
            op=None,
            sqn=None,
            apn='internet',
            imei=None,
            headless=False,
            no_default_route=False,
            no_dns=False,
            log_level='info',
        )
        defaults = dict(vars(options))
        proposals = apply_file_config(options, defaults, os.path.join('profiles', name))
        return options, proposals

    def test_invalid_ke_offers_768_then_2048(self):
        options, proposals = self._load('invalid_ke.yaml')
        self.assertEqual(proposals['ike_sa'][0][-1], [D_H, MODP_768_bit])
        self.assertEqual(proposals['ike_sa'][1][-1], [D_H, MODP_2048_bit])
        self.assertTrue(options.headless)

    def test_no_proposal_offers_des_only(self):
        _, proposals = self._load('no_proposal.yaml')
        self.assertEqual(len(proposals['ike_sa']), 1)
        self.assertEqual(proposals['ike_sa'][0][1], [ENCR, ENCR_DES])

    def test_auth_failed_flips_ki(self):
        options, _ = self._load('auth_failed.yaml')
        self.assertEqual(options.ki, '000102030405060708090a0b0c0d0e00')

    def test_auts_sync_sets_sqn(self):
        options, _ = self._load('auts_sync.yaml')
        self.assertEqual(options.sqn, '000000000001')

    def test_24_302_identity_and_apn(self):
        unknown, _ = self._load('user_unknown.yaml')
        self.assertEqual(unknown.imsi, '001019999999999')
        no_apn, _ = self._load('no_apn.yaml')
        self.assertEqual(no_apn.apn, 'nosuch.apn')
        illegal, _ = self._load('illegal_me.yaml')
        self.assertEqual(illegal.imei, '000000000000000')


class LoggingAndArgparse(unittest.TestCase):

    def test_connected_event_line(self):
        self.assertEqual(
            format_connected_event('internet', '192.168.64.1', ['10.10.42.134'], []),
            'event=connected apn=internet dest=192.168.64.1 ipv4=10.10.42.134 ipv6=-',
        )

    def test_ike_event_lines(self):
        self.assertEqual(notify_name(24), 'AUTHENTICATION_FAILED')
        self.assertEqual(notify_name(AUTHENTICATION_FAILED), 'AUTHENTICATION_FAILED')
        self.assertEqual(notify_name(USER_UNKNOWN), 'USER_UNKNOWN')
        self.assertEqual(notify_name(99999), '99999')
        self.assertEqual(
            format_ike_event(OTHER_ERROR, '24'),
            'event=failed notify=AUTHENTICATION_FAILED code=24',
        )
        self.assertEqual(
            format_ike_event(OTHER_ERROR, str(NO_PROPOSAL_CHOSEN)),
            'event=failed notify=NO_PROPOSAL_CHOSEN code=14',
        )
        self.assertEqual(
            format_ike_event(OTHER_ERROR, str(NO_APN_SUBSCRIPTION)),
            'event=failed notify=NO_APN_SUBSCRIPTION code=9002',
        )
        self.assertEqual(
            format_ike_event(REPEAT_STATE, 'INVALID_KE_PAYLOAD'),
            'event=retry notify=INVALID_KE_PAYLOAD',
        )
        self.assertEqual(
            format_ike_event(OTHER_ERROR, 'INVALID_KE_PAYLOAD'),
            'event=failed notify=INVALID_KE_PAYLOAD',
        )
        self.assertEqual(
            format_ike_event(REPEAT_STATE, 'SYNC FAILURE'),
            'event=retry reason=SYNC_FAILURE',
        )
        self.assertEqual(
            format_ike_event(OTHER_ERROR, 'EAP FAILURE'),
            'event=failed reason=EAP_FAILURE',
        )
        self.assertEqual(
            format_ike_event(OTHER_ERROR, 'LIVENESS TIMEOUT'),
            'event=failed reason=LIVENESS_TIMEOUT',
        )
        self.assertEqual(
            format_ike_event(REPEAT_STATE, 'EAP IDENTITY REQUESTED'),
            'event=retry reason=EAP_IDENTITY_REQUESTED',
        )
        self.assertEqual(
            format_ike_event(REPEAT_STATE, 'RECONNECT'),
            'event=retry reason=RECONNECT',
        )

    def test_resolve_dpd_seconds(self):
        self.assertEqual(resolve_dpd_seconds(None, None), 30)
        self.assertEqual(resolve_dpd_seconds(0, 60), 0)
        self.assertEqual(resolve_dpd_seconds(45, 10), 45)
        self.assertEqual(resolve_dpd_seconds(None, 10), 10)
        with self.assertRaises(ValueError):
            resolve_dpd_seconds(-1, None)

    def test_resolve_keepalive_and_reconnect(self):
        self.assertEqual(resolve_keepalive_seconds(None), 20)
        self.assertEqual(resolve_keepalive_seconds(0), 0)
        self.assertEqual(resolve_keepalive_seconds(15), 15)
        with self.assertRaises(ValueError):
            resolve_keepalive_seconds(-1)
        self.assertEqual(resolve_reconnect_attempts(None), 0)
        self.assertEqual(resolve_reconnect_attempts(0), 0)
        self.assertEqual(resolve_reconnect_attempts(3), 3)
        with self.assertRaises(ValueError):
            resolve_reconnect_attempts(-1)

    def test_log_level(self):
        self.assertEqual(normalize_log_level('WARNING'), 'warning')
        self.assertEqual(normalize_log_level(None), 'info')
        with self.assertRaises(ValueError):
            normalize_log_level('trace')

    def test_argparse_defaults(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--imsi', dest='imsi')
        parser.add_argument('--headless', dest='headless', action='store_true', default=False)
        defaults = argparse_defaults(parser)
        self.assertIsNone(defaults['imsi'])
        self.assertFalse(defaults['headless'])

    def test_aka_credentials(self):
        validate_aka_credentials(None, None, None, None)
        validate_aka_credentials('001011234567890', None, None, None)
        validate_aka_credentials(
            '001011234567890', '00' * 16, '11' * 16, None)
        validate_aka_credentials(
            '001011234567890', '00' * 16, None, '22' * 16)
        validate_aka_credentials(None, '00' * 16, '11' * 16, None)
        with self.assertRaises(ValueError):
            validate_aka_credentials('001011234567890', '00' * 16, None, None)

    def test_filter_ike_sa_by_dh(self):
        sa_list = [
            [[IKE, 0], [D_H, MODP_1024_bit]],
            [[IKE, 0], [D_H, ECP_521_bit]],
        ]
        self.assertEqual(filter_ike_sa_by_dh(sa_list, ECP_521_bit), [sa_list[1]])
        self.assertEqual(filter_ike_sa_by_dh(sa_list, MODP_768_bit), [])


class Ipv6Host(unittest.TestCase):

    def test_compressed_cfg_reply_stays_global(self):
        self.assertEqual(format_ipv6_host('2001:db8:beef::'), '2001:db8:beef::')
        self.assertNotEqual(format_ipv6_host('2001:db8:beef::')[:5], 'fe80:')


class EapIdentity(unittest.TestCase):
    # Same dummy IMSI as swu.yaml (3GPP TS 35.208 set-1), dummy PLMN.
    IMSI = '001011234567890'
    MNC = '001'
    MCC = '001'
    NAI = '0001011234567890@nai.epc.mnc001.mcc001.3gppnetwork.org'

    def test_permanent_nai(self):
        self.assertEqual(eap_permanent_nai(self.IMSI, self.MNC, self.MCC), self.NAI)

    def test_identity_response_matches_rfc3748(self):
        encoded = encode_eap_identity_response(1, self.NAI)
        self.assertEqual(encoded[0], EAP_RESPONSE)
        self.assertEqual(encoded[1], 1)
        self.assertEqual(encoded[4], EAP_IDENTITY)
        length = int.from_bytes(encoded[2:4], 'big')
        self.assertEqual(length, len(encoded))
        self.assertEqual(encoded[5:].decode('utf-8'), self.NAI)

    def test_identity_request_detection(self):
        prompt = b'ePDG wants your identity'
        decoded = [EAP_REQUEST, 1, EAP_IDENTITY, prompt]
        self.assertTrue(is_eap_identity_request(decoded))
        self.assertFalse(
            is_eap_identity_request([EAP_REQUEST, 1, EAP_AKA, 1, []])
        )
        reply = eap_identity_reply(decoded, self.IMSI, self.MNC, self.MCC)
        self.assertEqual(reply, encode_eap_identity_response(1, self.NAI))
        self.assertIsNone(
            eap_identity_reply([EAP_REQUEST, 1, EAP_AKA, 1, []], '1', '001', '001')
        )


class DeviceIdentity(unittest.TestCase):

    def test_accepts_none_and_valid(self):
        self.assertEqual(validate_device_identity(None, None), (None, None))
        self.assertEqual(
            validate_device_identity('123456789012347', '1234567890123456'),
            ('123456789012347', '1234567890123456'),
        )

    def test_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            validate_device_identity('123', None)
        with self.assertRaises(ValueError):
            validate_device_identity(None, '123')


if __name__ == '__main__':
    unittest.main()

import unittest

try:
    from usim_aka import byte_xor, milenage_res_ck_ik, return_auts, return_res_ck_ik
    _AKA_IMPORT_ERROR = None
except ImportError as exc:
    byte_xor = milenage_res_ck_ik = return_auts = return_res_ck_ik = None
    _AKA_IMPORT_ERROR = exc

# 3GPP TS 35.208 test set 1
KI = '465b5ce8b199b49faa5f0a2ee238a6bc'
OP = 'cdc202d5123e20f62b6d676ac72cb318'
OPC = 'cd63cb71954a9f4e48a5994e37a02baf'
RAND = '23553cbe9637a89d218ae64dae47bf35'
RES = b'a54211d5e3ba50bf'
CK = b'b40ba9a3c58b2a05bbf0d987b21bf8cb'
IK = b'f769bcd751044604127672711c6d3441'
SQN = 'ff9bb4d0b607'
AMF = 'b9b9'
AK_STAR = bytes.fromhex('451e8beca43b')
MAC_S = bytes.fromhex('01cfaf9ec4e871e9')
CONCEALED_SQN = bytes(a ^ b for a, b in zip(bytes.fromhex(SQN), AK_STAR))
DUMMY_AUTN = '00' * 16


@unittest.skipIf(_AKA_IMPORT_ERROR, str(_AKA_IMPORT_ERROR))
class MilenageVectors(unittest.TestCase):

    def test_res_ck_ik_from_op(self):
        res, ck, ik = milenage_res_ck_ik(KI, OP, None, RAND)
        self.assertEqual(res.lower(), RES)
        self.assertEqual(ck.lower(), CK)
        self.assertEqual(ik.lower(), IK)

    def test_res_ck_ik_from_opc(self):
        res, ck, ik = milenage_res_ck_ik(KI, None, OPC, RAND)
        self.assertEqual(res.lower(), RES)
        self.assertEqual(ck.lower(), CK)
        self.assertEqual(ik.lower(), IK)

    def test_return_res_ck_ik_uses_milenage(self):
        res, ck, ik = return_res_ck_ik(None, RAND, None, KI, OP, None)
        self.assertEqual(res.lower(), RES)
        self.assertEqual(ck.lower(), CK)
        self.assertEqual(ik.lower(), IK)

    def test_auts_from_op(self):
        auts = return_auts(RAND, DUMMY_AUTN, KI, OP, None, SQN, AMF)
        self.assertEqual(auts[:6], CONCEALED_SQN)
        self.assertEqual(auts[6:], MAC_S)

    def test_auts_from_opc(self):
        auts = return_auts(RAND, DUMMY_AUTN, KI, None, OPC, SQN, AMF)
        self.assertEqual(auts[:6], CONCEALED_SQN)
        self.assertEqual(auts[6:], MAC_S)

    def test_auts_default_amf_is_zero(self):
        official = return_auts(RAND, DUMMY_AUTN, KI, OP, None, SQN, AMF)
        default = return_auts(RAND, DUMMY_AUTN, KI, OP, None, SQN)
        self.assertEqual(default[:6], CONCEALED_SQN)
        self.assertEqual(len(default), 14)
        self.assertNotEqual(default[6:], official[6:])

    def test_byte_xor(self):
        self.assertEqual(byte_xor(b'\x01\x02', b'\xff\x01'), b'\xfe\x03')


if __name__ == '__main__':
    unittest.main()

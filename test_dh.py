import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from ikev2_const import ECP_256_bit, ECP_384_bit, ECP_521_bit
from swu_emulator import ECDH_CURVES, ecdh_decode_public, ecdh_encode_public, ecdh_field_len


class EcdhGroups(unittest.TestCase):

    def test_ke_lengths_and_agreement(self):
        expected = (
            (ECP_256_bit, 64),
            (ECP_384_bit, 96),
            (ECP_521_bit, 132),
        )
        for group, ke_len in expected:
            curve = ECDH_CURVES[group]
            alice = ec.generate_private_key(curve)
            bob = ec.generate_private_key(curve)
            alice_pub = ecdh_encode_public(alice.public_key())
            bob_pub = ecdh_encode_public(bob.public_key())
            self.assertEqual(len(alice_pub), ke_len)
            self.assertEqual(len(bob_pub), ke_len)
            secret_a = alice.exchange(ec.ECDH(), ecdh_decode_public(curve, bob_pub))
            secret_b = bob.exchange(ec.ECDH(), ecdh_decode_public(curve, alice_pub))
            self.assertEqual(secret_a, secret_b)
            self.assertEqual(len(secret_a), ecdh_field_len(curve))

    def test_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            ecdh_decode_public(ECDH_CURVES[ECP_256_bit], b'\x00' * 32)


if __name__ == '__main__':
    unittest.main()

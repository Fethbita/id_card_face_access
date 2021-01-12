#!/usr/bin/env python3
"""This module has the necessary tests of functions"""

import unittest
from id_card_face_access.card_comms import APDU
from id_card_face_access.bac import (
    compute_key,
    compute_mac,
    secure_messaging,
    process_rapdu,
)
from id_card_face_access.mrz import calculate_check_digit


class TestMethods(unittest.TestCase):
    def test_calculate_check_digit(self):
        self.assertEqual(calculate_check_digit("D23145890734"), "9")
        self.assertEqual(calculate_check_digit("340712"), "7")
        self.assertEqual(calculate_check_digit("950712"), "2")

        self.assertEqual(calculate_check_digit("L898902C<"), "3")
        self.assertEqual(calculate_check_digit("690806"), "1")
        self.assertEqual(calculate_check_digit("940623"), "6")

    def test_compute_key(self):
        key_seed = bytes.fromhex("239AB9CB282DAF66231DC5A4DF6BFBAE")
        self.assertEqual(
            compute_key(key_seed, "enc"),
            bytes.fromhex("AB94FDECF2674FDFB9B391F85D7F76F2"),
        )
        self.assertEqual(
            compute_key(key_seed, "mac"),
            bytes.fromhex("7962D9ECE03D1ACD4C76089DCE131543"),
        )

        key_seed = bytes.fromhex("0036D272F5C350ACAC50C3F572D23600")
        self.assertEqual(
            compute_key(key_seed, "enc"),
            bytes.fromhex("979EC13B1CBFE9DCD01AB0FED307EAE5"),
        )
        self.assertEqual(
            compute_key(key_seed, "mac"),
            bytes.fromhex("F1CB1F1FB5ADF208806B89DC579DC1F8"),
        )

    def test_compute_mac(self):
        key = bytes.fromhex("7962D9ECE03D1ACD4C76089DCE131543")
        data = bytes.fromhex(
            "72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2"
        )
        self.assertEqual(compute_mac(key, data), bytes.fromhex("5F1448EEA8AD90A7"))
        data = bytes.fromhex(
            "46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F"
        )
        self.assertEqual(compute_mac(key, data), bytes.fromhex("2F2D235D074D7449"))

        key = bytes.fromhex("F1CB1F1FB5ADF208806B89DC579DC1F8")
        data = bytes.fromhex("887022120C06C2270CA4020C800000008709016375432908C044F6")
        self.assertEqual(compute_mac(key, data), bytes.fromhex("BF8B92D635FF24F8"))
        data = bytes.fromhex("887022120C06C22899029000")
        self.assertEqual(compute_mac(key, data), bytes.fromhex("FA855A5D4C50A8ED"))

    def test_secure_messaging(self):
        ks_enc = bytes.fromhex("979EC13B1CBFE9DCD01AB0FED307EAE5")
        ks_mac = bytes.fromhex("F1CB1F1FB5ADF208806B89DC579DC1F8")

        SSC = bytes.fromhex("887022120C06C226")
        apdu = APDU(b"\x00", b"\xA4", b"\x02", b"\x0C", Lc=b"\x02", cdata=b"\x01\x1E")
        protected_apdu, SSC = secure_messaging(ks_enc, ks_mac, SSC, apdu)
        self.assertEqual(
            protected_apdu,
            bytes.fromhex("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800"),
        )
        self.assertEqual(SSC, bytes.fromhex("887022120C06C227"))

        SSC = bytes.fromhex("887022120C06C228")
        apdu = APDU(b"\x00", b"\xB0", b"\x00", b"\x00", Le=b"\x04")
        protected_apdu, SSC = secure_messaging(ks_enc, ks_mac, SSC, apdu)
        self.assertEqual(
            protected_apdu, bytes.fromhex("0CB000000D9701048E08ED6705417E96BA5500")
        )
        self.assertEqual(SSC, bytes.fromhex("887022120C06C229"))

        SSC = bytes.fromhex("887022120C06C22A")
        apdu = APDU(b"\x00", b"\xB0", b"\x00", b"\x04", Le=b"\x12")
        protected_apdu, SSC = secure_messaging(ks_enc, ks_mac, SSC, apdu)
        self.assertEqual(
            protected_apdu, bytes.fromhex("0CB000040D9701128E082EA28A70F3C7B53500")
        )
        self.assertEqual(SSC, bytes.fromhex("887022120C06C22B"))

    def test_process_rapdu(self):
        ks_mac = bytes.fromhex("F1CB1F1FB5ADF208806B89DC579DC1F8")

        SSC = bytes.fromhex("887022120C06C227")
        apdu = APDU(b"\x00", b"\xA4", b"\x02", b"\x0C", Lc=b"\x02", cdata=b"\x01\x1E")
        rapdu = bytes.fromhex("990290008E08FA855A5D4C50A8ED9000")
        SSC, decrypted_data = process_rapdu(ks_mac, SSC, apdu, rapdu)
        self.assertIsNone(decrypted_data)
        self.assertEqual(SSC, bytes.fromhex("887022120C06C228"))

        ks_enc = ks_enc = bytes.fromhex("979EC13B1CBFE9DCD01AB0FED307EAE5")

        SSC = bytes.fromhex("887022120C06C229")
        apdu = APDU(b"\x00", b"\xB0", b"\x00", b"\x00", Le=b"\x04")
        rapdu = bytes.fromhex("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000")
        SSC, decrypted_data = process_rapdu(ks_mac, SSC, apdu, rapdu, ks_enc=ks_enc)
        self.assertEqual(decrypted_data, bytes.fromhex("60145F01"))
        self.assertEqual(SSC, bytes.fromhex("887022120C06C22A"))

        SSC = bytes.fromhex("887022120C06C22B")
        apdu = APDU(b"\x00", b"\xB0", b"\x00", b"\x04", Le=b"\x12")
        rapdu = bytes.fromhex(
            "871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D749000"
        )
        SSC, decrypted_data = process_rapdu(ks_mac, SSC, apdu, rapdu, ks_enc=ks_enc)
        self.assertEqual(
            decrypted_data, bytes.fromhex("04303130365F36063034303030305C026175")
        )
        self.assertEqual(SSC, bytes.fromhex("887022120C06C22C"))


if __name__ == "__main__":
    unittest.main()

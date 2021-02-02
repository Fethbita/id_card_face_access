#!/usr/bin/env python3
"""This module does Active Authentication (AA)"""

import hashlib
import hmac

from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from OpenSSL.crypto import X509, load_publickey, FILETYPE_ASN1
import PySimpleGUI as sg

from asn1_tiny_decoder.source.data.asn1tinydecoder import (
    asn1_node_root,
    asn1_get_all,
    asn1_node_first_child,
)
from id_card_face_access.card_comms import send, APDU
from id_card_face_access.bac import secure_messaging, process_rapdu
from id_card_face_access.asn1 import dump_asn1, encode_oid_string
from id_card_face_access.gui import window_update


def active_auth(dg15, channel, ks_enc, ks_mac, SSC, window, dump=False):
    # Generate 8 random bytes
    rnd_ifd = get_random_bytes(8)

    apdu = APDU(
        b"\x00", b"\x88", b"\x00", b"\x00", Lc=b"\x08", cdata=rnd_ifd, Le=b"\x00"
    )
    protected_apdu, SSC = secure_messaging(ks_enc, ks_mac, SSC, apdu)
    rapdu = send(channel, list(protected_apdu))
    SSC, data = process_rapdu(ks_mac, SSC, apdu, rapdu, ks_enc)

    i = asn1_node_root(dg15)
    i = asn1_node_first_child(dg15, i)
    pub_key = asn1_get_all(dg15, i)
    if dump:
        print(dump_asn1(pub_key))

    i = asn1_node_first_child(dg15, i)
    i = asn1_node_first_child(dg15, i)

    if asn1_get_all(dg15, i) == encode_oid_string("1.2.840.10045.2.1"):  # ECC
        pub_key = load_publickey(FILETYPE_ASN1, pub_key)
        cert = X509()
        cert.set_pubkey(pub_key)

        # if verify(cert, data, rnd_ifd, "sha1") is None:
        #    print("[+] The signature on EF_SOD is valid.")

        print("[!] Active authentication is still not implemented!")

    elif asn1_get_all(dg15, i) == encode_oid_string("1.2.840.113549.1.1.1"):  # RSA
        rsa_key = RSA.import_key(pub_key)
        # https://stackoverflow.com/a/60132608/6077951

        msg = int.from_bytes(data, byteorder="big")
        dec = pow(msg, rsa_key.e, rsa_key.n)
        dec = dec.to_bytes(len(data), byteorder="big")

        if dec[-1] == 0xCC:
            if dec[-2] == 0x38:
                hash_alg = "sha224"
            elif dec[-2] == 0x34:
                hash_alg = "sha256"
            elif dec[-2] == 0x36:
                hash_alg = "sha384"
            elif dec[-2] == 0x35:
                hash_alg = "sha512"
            t = 2
        elif dec[-1] == 0xBC:
            hash_alg = "sha1"
            t = 1
        else:
            raise ValueError("[-] Error while Active Authentication!")

        def compare_aa(hash_object):
            # k = rsa_key.size_in_bits()
            # Lh = hash_object.digest_size * 8
            # Lm1 = (k - Lh - (8 * t) - 4 - 4) // 8
            D = dec[-hash_object.digest_size - t : -t]
            M1 = dec[1 : -hash_object.digest_size - t]
            Mstar = M1 + rnd_ifd
            hash_object.update(Mstar)
            Dstar = hash_object.digest()
            if hmac.compare_digest(D, Dstar):
                return True
            else:
                return False

        hash_object = hashlib.new(hash_alg)
        if compare_aa(hash_object):
            print("[+] Active Authentication (AA) completed successfully!")
        else:
            from id_card_face_access.__main__ import EVERYTHING_IS_OKAY
            EVERYTHING_IS_OKAY = False
            print("[-] Active Authentication (AA) failed!")
            #reply = input("[?] Do you still want to proceed? [y/N] ")
            #if reply.lower() != "y":
            #    raise ValueError("[-] Active Authentication (AA) failed!")
            ## GUI ##
            window['text_instruction'].update("Active Authentication (AA) failed! Check logs! [Enter] to continue [Escape] to stop.", text_color="red")
            window_update(window)
            ## GUI ##
            while True:
                event, values = window.read(timeout=20)

                if event == 'Exit' or event == sg.WIN_CLOSED:
                    exit(0)
                elif event.startswith("Return"):
                    break
                elif event.startswith("Escape"):
                    exit(1)

    return SSC

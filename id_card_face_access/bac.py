#!/usr/bin/env python3
"""This module has functions for BAC and Secure Messaging (SM)"""

import hashlib

from Crypto.Cipher import DES, DES3
from Crypto.Util.strxor import strxor
from Crypto.Random import get_random_bytes
from pyasn1.type import univ, tag
from pyasn1.codec.ber import encoder, decoder

from id_card_face_access.card_comms import send, APDU
from id_card_face_access.asn1 import len2int
from id_card_face_access.byte_operations import (
    padding_method_2,
    increment_bytes,
    remove_padding,
    nb,
)

# I don't know how I would have SM Data Objects written as a class.
# Untagged sequence seems to not be a thing and Choice also adds a tag of it's own
# Which in these BER TLV's we don't have any tags other than the ones we use
class DO85(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)
    )


class DO87(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)
    )


class DO97(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 23)
    )


class DO99(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 25)
    )


class DO8E(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 14)
    )


def compute_key(key_seed, key_type="enc"):
    """Compute enc and mac keys from key_seed.

    :key_seed key_seed:  16 bytes
    :key_type key_type: type of key to be created (default "enc") (choices "enc", "mac")
    :returns: 3DES key
    """
    if key_type == "enc":
        c = bytes([0, 0, 0, 1])
    elif key_type == "mac":
        c = bytes([0, 0, 0, 2])
    else:
        return False
    D = key_seed + c
    hash_of_D = hashlib.sha1(D).hexdigest()
    K_a = bytes.fromhex(hash_of_D[:16])
    K_b = bytes.fromhex(hash_of_D[16:32])
    return DES3.adjust_key_parity(K_a + K_b)  # set parity bits


def compute_mac(key, data):
    """
    Calculate message authentication code (mac) of data using key
    according toIEC_9797-1 MAC algorithm 3
    https://en.wikipedia.org/wiki/ISO/IEC_9797-1 MAC algorithm 3\n
    http://www.devinvenable.com/mediawiki/index.php/ISO_9797_algorithm_3

    :key key: DES key to compute the mac with, 16 bytes
    :data data: data to calculate the mac of
    :returns: mac of data
    """

    m_cipher1 = DES.new(key[:8], DES.MODE_ECB)
    m_cipher2 = DES.new(key[-8:], DES.MODE_ECB)

    h = m_cipher1.encrypt(data[:8])
    data = padding_method_2(data, 8)
    for i in range(1, len(data) // 8):
        h = m_cipher1.encrypt(strxor(h, data[8 * i : 8 * (i + 1)]))
    mac_x = m_cipher1.encrypt(m_cipher2.decrypt(h))
    return mac_x


def establish_session_keys(channel, mrz_information):
    """
    This function establishes session keys with the card
    Takes card channel and mrz info
    returns (ks_enc, ks_mac, SSC)
    """
    # Calculate the SHA-1 hash of ‘MRZ_information’ and
    # take the most significant 16 bytes to form the basic access key seed
    ba_key_seed = hashlib.sha1(mrz_information.encode("utf-8")).digest()[:16]
    # Calculate the basic access keys (ba_key_enc and ba_key_mac)
    print("[+] Computing basic access keys...")
    ba_key_enc = compute_key(ba_key_seed, "enc")
    ba_key_mac = compute_key(ba_key_seed, "mac")

    ## AUTHENTICATION AND ESTABLISHMENT OF SESSION KEYS ##
    print("[+] Establishing session keys...")
    rnd_ic = send(channel, [0x00, 0x84, 0x00, 0x00, 0x08])

    rnd_ifd = get_random_bytes(8)
    k_ifd = get_random_bytes(16)
    s = rnd_ifd + rnd_ic + k_ifd
    e_cipher = DES3.new(ba_key_enc, DES3.MODE_CBC, bytes([0] * 8))
    e_ifd = e_cipher.encrypt(s)
    m_ifd = compute_mac(ba_key_mac, e_ifd)
    # Construct command data for EXTERNAL AUTHENTICATE
    cmd_data = e_ifd + m_ifd

    resp_data_enc = send(
        channel, [0x00, 0x82, 0x00, 0x00, len(cmd_data)] + list(cmd_data) + [0x28]
    )
    m_ic = compute_mac(ba_key_mac, resp_data_enc[:-8])
    if m_ic != resp_data_enc[-8:]:
        raise ValueError("Encrypted message MAC is not correct!")

    d_cipher = DES3.new(ba_key_enc, DES3.MODE_CBC, bytes([0] * 8))
    resp_data = d_cipher.decrypt(resp_data_enc[:-8])
    if resp_data[:8] != rnd_ic:
        raise ValueError("Received RND.IC DOES NOT match with the earlier RND.IC")
    if resp_data[8:16] != rnd_ifd:
        raise ValueError("Received RND.IFD DOES NOT match with the generated RND.IFD")

    k_ic = resp_data[16:]

    # Calculate XOR of KIFD and KIC
    ses_key_seed = strxor(k_ifd, k_ic)
    # Calculate session keys (ks_enc and ks_mac)
    print("[+] Computing session keys...")
    ks_enc = compute_key(ses_key_seed, "enc")
    ks_mac = compute_key(ses_key_seed, "mac")

    # Calculate send sequence counter
    SSC = rnd_ic[-4:] + rnd_ifd[-4:]
    return ks_enc, ks_mac, SSC


def secure_messaging(ks_enc, ks_mac, SSC, apdu):
    cmdHeader = padding_method_2(apdu.get_command_header(), 8)

    m = cmdHeader
    payload = b""
    if apdu.cdata is not None:
        data = padding_method_2(apdu.cdata, 8)
        e_cipher = DES3.new(ks_enc, DES3.MODE_CBC, bytes([0] * 8))
        encryptedData = e_cipher.encrypt(data)
        if int.from_bytes(apdu.ins, byteorder="big") % 2 == 0:
            # For a command with even INS, any command data is encrypted
            # and capsulated in aTag 87 with padding indicator (01).
            encryptedData = b"\x01" + encryptedData
            do87 = encoder.encode(encryptedData, asn1Spec=DO87)
            m += do87
            payload += do87
        else:
            # For a command with odd INS, any command data is encrypted
            # and capsulated in a Tag 85 without padding indicator.
            do85 = encoder.encode(encryptedData, asn1Spec=DO85)
            m += do85
            payload += do85

    if apdu.Le is not None:
        # Commands with response (Le field not empty)
        # have a protected Le-field (Tag 97) in the command data.
        do97 = encoder.encode(apdu.Le, asn1Spec=DO97)
        m += do97
        payload += do97

    SSC = increment_bytes(SSC)
    n = SSC + m
    cc = compute_mac(ks_mac, n)

    do8e = encoder.encode(cc, asn1Spec=DO8E)

    payload += do8e
    protected_apdu = (
        apdu.get_command_header() + bytes([len(payload)]) + payload + b"\x00"
    )

    return protected_apdu, SSC


def process_rapdu(ks_mac, SSC, apdu, rapdu, ks_enc=None):
    """
    Verify the MAC of the received APDU and return the decrypted data if it exists

    :ks_mac ks_mac: MAC session key, used for verifying the rapdu mac
    :SSC SSC: Send sequence counter (SSC)
    :apdu apdu: Sent APDU
    :rapdu rapdu: Received Reply APDU
    :ks_enc ks_enc: Encryption session key, used for decrypting the data if it exists
    :returns: SSC, decrypted_data
    """

    class DecoderTLV(decoder.Decoder):
        """
        Taken from https://stackoverflow.com/q/50299018
        """

        def __call__(self, *v, **kw):
            _, remainder = decoder.Decoder.__call__(self, *v, **kw)
            return v[0][: len(v[0]) - len(remainder)], remainder

    decode_tlv = DecoderTLV(decoder.tagMap, decoder.typeMap)

    encrypted_data, decrypted_data = None, None
    try:
        encrypted_data, _ = decoder.decode(rapdu, asn1Spec=DO85)
        do85, rapdu = decode_tlv(rapdu, asn1Spec=DO85)
    except TypeError:
        do85 = None
    try:
        encrypted_data, _ = decoder.decode(rapdu, asn1Spec=DO87)
        do87, rapdu = decode_tlv(rapdu, asn1Spec=DO87)
    except TypeError:
        do87 = None
    try:
        do99, rapdu = decode_tlv(rapdu, asn1Spec=DO99)
    except TypeError:
        do99 = None

    if encrypted_data and not ks_enc:
        raise ValueError("If Encrypted data exists ks_enc should be given.")

    do8e, rapdu = decoder.decode(rapdu, asn1Spec=DO8E)

    SSC = increment_bytes(SSC)
    k = SSC + (do85 or b"") + (do87 or b"") + (do99 or b"")

    cc = compute_mac(ks_mac, k)

    if cc != do8e:
        raise ValueError("Reply APDU is not valid.")

    if encrypted_data:
        # If INS is even, remove the padding indicator (01)
        if int.from_bytes(apdu.ins, byteorder="big") % 2 == 0:
            encrypted_data = encrypted_data[1:]
        # Decrypt
        d_cipher = DES3.new(ks_enc, DES3.MODE_CBC, bytes([0] * 8))
        decrypted_data = d_cipher.decrypt(encrypted_data)
        # Remove padding
        decrypted_data = remove_padding(decrypted_data)

    return SSC, decrypted_data


def read_data_from_ef(channel, ks_enc, ks_mac, SSC, fid, fname):
    # Select EF.COM
    print("[+] Selecting file: " + fname)
    apdu = APDU(b"\x00", b"\xA4", b"\x02", b"\x0C", Lc=b"\x02", cdata=fid)
    protected_apdu, SSC = secure_messaging(ks_enc, ks_mac, SSC, apdu)

    rapdu = send(channel, list(protected_apdu))
    SSC, _ = process_rapdu(ks_mac, SSC, apdu, rapdu)

    # Read Binary of first four bytes
    print("[+] Read first 4 bytes of selected file...")
    apdu = APDU(b"\x00", b"\xB0", b"\x00", b"\x00", Le=b"\x04")
    protected_apdu, SSC = secure_messaging(ks_enc, ks_mac, SSC, apdu)

    rapdu = send(channel, list(protected_apdu))
    SSC, data = process_rapdu(ks_mac, SSC, apdu, rapdu, ks_enc)

    data_len = len2int(data)

    offset = 4

    # Read the rest of the bytes
    print("[+] Read the rest of the bytes of selected file...")
    # IAS_ECC_v1 page 121 "Particular issue for the READ BINARY command"
    for _ in range((data_len - 4) // 0xE7):
        apdu = APDU(
            b"\x00",
            b"\xB0",
            bytes([nb(offset, 2)[0]]),
            bytes([nb(offset, 2)[1]]),
            Le=b"\xE7",
        )
        protected_apdu, SSC = secure_messaging(ks_enc, ks_mac, SSC, apdu)

        rapdu = send(channel, list(protected_apdu))
        SSC, decrypted_data = process_rapdu(ks_mac, SSC, apdu, rapdu, ks_enc)
        data += decrypted_data
        offset += len(decrypted_data)

    if (data_len - 4) % 0xE7 > 0:
        apdu = APDU(
            b"\x00",
            b"\xB0",
            bytes([nb(offset, 2)[0]]),
            bytes([nb(offset, 2)[1]]),
            Le=bytes([(data_len - 4) % 0xE7]),
        )
        protected_apdu, SSC = secure_messaging(ks_enc, ks_mac, SSC, apdu)

        rapdu = send(channel, list(protected_apdu))
        SSC, decrypted_data = process_rapdu(ks_mac, SSC, apdu, rapdu, ks_enc)
        data += decrypted_data
        offset += len(decrypted_data)

    if offset != data_len:
        raise Exception("Error while processing a file.")
    return SSC, data

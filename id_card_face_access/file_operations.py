#!/usr/bin/env python3
"""This module has functions related to Data Groups (DG) in MRTD"""

import hashlib
import hmac
import PySimpleGUI as sg

from asn1_tiny_decoder.source.data.asn1tinydecoder import (
    asn1_node_root,
    asn1_get_value,
    asn1_get_value_of_type,
    asn1_node_next,
    asn1_node_first_child,
)
from id_card_face_access.gui import window_update



def parse_efcom(EFCOM):
    i = asn1_node_root(EFCOM)
    lst = list(i)
    # LDS Version length is 4
    lst[0] = lst[1]
    lst[1] = lst[0] + 3
    lst[2] = lst[1] + 3
    i = tuple(lst)
    lds_ver = asn1_get_value(EFCOM, i)
    #print("[+] LDS version: {}.{}".format(*[int(lds_ver[i : i + 2].decode("utf-8")) for i in range(0, 4, 2)]))

    # Unicode Version number length is 6
    lst[0] = lst[2] + 1
    lst[1] = lst[0] + 3
    lst[2] = lst[1] + 5
    i = tuple(lst)
    unicode_ver = asn1_get_value(EFCOM, i)
    #print("[+] Unicode version: {}.{}.{}".format(*[int(unicode_ver[i : i + 2].decode("utf-8")) for i in range(0, 6, 2)]))

    i = asn1_node_next(EFCOM, i)
    rest = asn1_get_value(EFCOM, i)

    tag2dg = {
        0x60: [b"\x1E", "EF.COM"],
        0x61: [b"\x01", "EF.DG1"],
        0x75: [b"\x02", "EF.DG2"],
        0x63: [b"\x03", "EF.DG3"],
        0x76: [b"\x04", "EF.DG4"],
        0x65: [b"\x05", "EF.DG5"],
        0x66: [b"\x06", "EF.DG6"],
        0x67: [b"\x07", "EF.DG7"],
        0x68: [b"\x08", "EF.DG8"],
        0x69: [b"\x09", "EF.DG9"],
        0x6A: [b"\x0A", "EF.DG10"],
        0x6B: [b"\x0B", "EF.DG11"],
        0x6C: [b"\x0C", "EF.DG12"],
        0x6D: [b"\x0D", "EF.DG13"],
        0x6E: [b"\x0E", "EF.DG14"],
        0x6F: [b"\x0F", "EF.DG15"],
        0x70: [b"\x10", "EF.DG16"],
        0x77: [b"\x1D", "EF.SOD"],
    }

    dg_list = {tag2dg[byte][0]: tag2dg[byte][1] for byte in rest}

    return dg_list


def get_dg_numbers(data_group_hash_values):
    dg_list = []

    i = asn1_node_root(data_group_hash_values)
    last = i[2]
    i = asn1_node_first_child(data_group_hash_values, i)

    j = asn1_node_first_child(data_group_hash_values, i)
    dg_list.append(asn1_get_value_of_type(data_group_hash_values, j, "INTEGER"))
    while i[2] != last:
        i = asn1_node_next(data_group_hash_values, i)
        j = asn1_node_first_child(data_group_hash_values, i)
        dg_list.append(asn1_get_value_of_type(data_group_hash_values, j, "INTEGER"))

    tag2dg = {
        b"\x1E": "EF.COM",
        b"\x01": "EF.DG1",
        b"\x02": "EF.DG2",
        b"\x03": "EF.DG3",
        b"\x04": "EF.DG4",
        b"\x05": "EF.DG5",
        b"\x06": "EF.DG6",
        b"\x07": "EF.DG7",
        b"\x08": "EF.DG8",
        b"\x09": "EF.DG9",
        b"\x0A": "EF.DG10",
        b"\x0B": "EF.DG11",
        b"\x0C": "EF.DG12",
        b"\x0D": "EF.DG13",
        b"\x0E": "EF.DG14",
        b"\x0F": "EF.DG15",
        b"\x10": "EF.DG16",
        b"\x1D": "EF.SOD",
    }

    dg_list = {byte: tag2dg[byte] for byte in dg_list}

    return dg_list


def assert_dg_hash(dg_file, data_group_hash_values, hash_alg, dg_number, window):
    dg_number = int.from_bytes(dg_number, byteorder="big")
    # Only hashes for DG1-16 exist
    if dg_number < 1 and dg_number > 16:
        return

    hash_object = hashlib.new(hash_alg)

    hash_object.update(dg_file)
    file_hash = hash_object.digest()

    current = 0
    i = asn1_node_root(data_group_hash_values)
    i = asn1_node_first_child(data_group_hash_values, i)
    while True:
        j = asn1_node_first_child(data_group_hash_values, i)
        current = int.from_bytes(
            asn1_get_value_of_type(data_group_hash_values, j, "INTEGER"),
            byteorder="big",
        )
        if current == dg_number:
            break
        i = asn1_node_next(data_group_hash_values, i)

    j = asn1_node_next(data_group_hash_values, j)
    hash_in_dg = asn1_get_value(data_group_hash_values, j)

    if not hmac.compare_digest(file_hash, hash_in_dg):
        from id_card_face_access.__main__ import EVERYTHING_IS_OKAY
        EVERYTHING_IS_OKAY = False
        print("[-] Potentially cloned document, hashes do not match!")
        #reply = input("[?] Do you still want to proceed? [Y/n] ")
        #if reply.lower() != "y":
        #    raise ValueError("[-] Potentially cloned document, hashes do not match!")
        ## GUI ##
        window['text_instruction'].update("Potentially cloned document! Check logs! [Enter] to continue [Escape] to stop.", text_color="red")
        window_update(window)
        ## GUI ##
        while True:
            event, values = window.read(timeout=20)

            if event == 'Exit' or event == sg.WIN_CLOSED:
                exit(0)
            elif event.startswith("Return"):
                return
            elif event.startswith("Escape"):
                exit(1)
    print("[+] DG {} hash matches that on the EF.SOD.".format(dg_number))

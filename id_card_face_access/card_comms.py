#!/usr/bin/env python3
"""Functions related to card communication; APDU, APDU send etc."""

from typing import Optional
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.scard import SCARD_UNPOWER_CARD


class APDU:
    """an APDU class"""

    cla: bytes
    ins: bytes
    p1: bytes
    p2: bytes
    Lc: Optional[bytes] = None
    cdata: Optional[bytes] = None
    Le: Optional[bytes] = None

    def __init__(
        self,
        cla: bytes,
        ins: bytes,
        p1: bytes,
        p2: bytes,
        Lc: Optional[bytes] = None,
        cdata: Optional[bytes] = None,
        Le: Optional[bytes] = None,
    ):
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.Lc = Lc
        self.cdata = cdata
        self.Le = Le

        self.post_init()

    def post_init(self):
        if (
            len(self.cla) != 1
            or len(self.ins) != 1
            or len(self.p1) != 1
            or len(self.p2) != 1
        ):
            raise OverflowError("Cla, Ins, P1, P2 must be 1 byte")
        self.cla = b"\x0C"
        if self.Lc is not None and 1 != len(self.Lc) != 3:
            raise OverflowError("Lc must either be 1 byte or 3 bytes")
        if self.Le is not None and (
            (self.Lc is None and 1 != len(self.Le) != 3)
            or (self.Lc is not None and len(self.Lc) == 3 and len(self.Le) != 2)
        ):
            raise OverflowError("Le must either be 1 byte or 3 bytes")

    def get_command_header(self):
        """return the command's header"""
        return self.cla + self.ins + self.p1 + self.p2


def wait_for_card():
    channel = CardRequest(timeout=None).waitforcard().connection
    print("[+] Selected reader:", channel.getReader())
    try:
        channel.connect(CardConnection.T1_protocol, disposition=SCARD_UNPOWER_CARD)
    except:
        print("[!] Fallback to T=0")
        channel.connect(CardConnection.T0_protocol, disposition=SCARD_UNPOWER_CARD)
    return channel


def send(channel, apdu: list) -> bytes:
    """
    Send APDU to the channel and return the data if there are no errors.
    """
    data, sw1, sw2 = channel.transmit(apdu)

    # success
    if [sw1, sw2] == [0x90, 0x00]:
        return bytes(data)
    # signals that there is more data to read
    elif sw1 == 0x61:
        # print("[=] More data to read:", sw2)
        return send(channel, [0x00, 0xC0, 0x00, 0x00, sw2])  # GET RESPONSE of sw2 bytes
    elif sw1 == 0x6C:
        # print("[=] Resending with Le:", sw2)
        return send(channel, apdu[0:4] + [sw2])  # resend APDU with Le = sw2
    # probably error condition
    else:
        print(
            "Error: %02x %02x, sending APDU: %s"
            % (sw1, sw2, " ".join(["{:02x}".format(x) for x in apdu]).upper())
        )
        channel.disconnect()
        exit(1)

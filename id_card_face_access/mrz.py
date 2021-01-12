from id_card_face_access.card_comms import send


def calculate_check_digit(data):
    """Calculate MRZ check digits for data.

    :data data: Data to calculate the check digit of
    :returns: check digit
    """
    values = {
        "0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5,
        "6": 6, "7": 7, "8": 8, "9": 9, "<": 0, "A": 10,
        "B": 11, "C": 12, "D": 13, "E": 14, "F": 15, "G": 16,
        "H": 17, "I": 18, "J": 19, "K": 20, "L": 21, "M": 22,
        "N": 23, "O": 24, "P": 25, "Q": 26, "R": 27, "S": 28,
        "T": 29, "U": 30, "V": 31, "W": 32, "X": 33, "Y": 34, "Z": 35,
    }
    weights = [7, 3, 1]
    total = 0

    for counter, value in enumerate(data):
        total += weights[counter % 3] * values[value]
    return str(total % 10)


def estonia_read_mrz(channel):
    # reading personal data file (EstEID spec page 30)
    print("[+] Selecting IAS ECC applet AID: A000000077010800070000FE00000100...")
    ias_ecc_aid = bytes.fromhex("A000000077010800070000FE00000100")
    send(channel, [0x00, 0xA4, 0x04, 0x00, len(ias_ecc_aid)] + list(ias_ecc_aid))
    print("[+] Selecting DF ID: 5000...")
    send(channel, [0x00, 0xA4, 0x01, 0x0C] + [0x02, 0x50, 0x00])
    send(channel, [0x00, 0xA4, 0x01, 0x0C] + [0x02, 0x50, 0x07])
    print("[+] Reading personal data files...")
    document_number = send(channel, [0x00, 0xB0, 0x00, 0x00, 0x00]).decode("utf8")
    send(channel, [0x00, 0xA4, 0x01, 0x0C] + [0x02, 0x50, 0x05])
    date_of_birth = send(channel, [0x00, 0xB0, 0x00, 0x00, 0x00])[:10].decode("utf8")
    date_of_birth = date_of_birth[-2:] + date_of_birth[3:5] + date_of_birth[:2]
    send(channel, [0x00, 0xA4, 0x01, 0x0C] + [0x02, 0x50, 0x08])
    date_of_expiry = send(channel, [0x00, 0xB0, 0x00, 0x00, 0x00]).decode("utf8")
    date_of_expiry = date_of_expiry[-2:] + date_of_expiry[3:5] + date_of_expiry[:2]
    # Construct the 'MRZ information'
    print("[+] Constructing the MRZ information...")
    mrz_information = (
        document_number
        + calculate_check_digit(document_number)
        + date_of_birth
        + calculate_check_digit(date_of_birth)
        + date_of_expiry
        + calculate_check_digit(date_of_expiry)
    )

    send(channel, [0x00, 0xA4, 0x01, 0x0C] + [0x02, 0x50, 0x01])
    surname = send(channel, [0x00, 0xB0, 0x00, 0x00, 0x00]).decode("utf8")
    send(channel, [0x00, 0xA4, 0x01, 0x0C] + [0x02, 0x50, 0x02])
    name = send(channel, [0x00, 0xB0, 0x00, 0x00, 0x00]).decode("utf8")
    send(channel, [0x00, 0xA4, 0x01, 0x0C] + [0x02, 0x50, 0x06])
    personal_id_code = send(channel, [0x00, 0xB0, 0x00, 0x00, 0x00]).decode("utf8")

    # Select eMRTD applet
    # A00000024710FF is applet id
    print("[+] Selecting eMRTD applet AID: A00000024710FF...")
    aid = bytes.fromhex("A00000024710FF")
    send(channel, [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid) + [0x00])

    return mrz_information, document_number, personal_id_code, name, surname


def other_mrz(doc_no, birthdate, expirydate):
    doc_no = doc_no.upper()
    return (
        doc_no
        + calculate_check_digit(doc_no)
        + birthdate
        + calculate_check_digit(birthdate)
        + expirydate
        + calculate_check_digit(expirydate)
    )

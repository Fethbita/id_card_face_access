#!/usr/bin/env python3
"""This module gets the JPEG image from DG2"""

import cv2


def get_jpeg_im(EF_DG2):
    # TODO ICAO9303-10 and ISO/IEC 19794-5
    im_start = EF_DG2.find(b"\xFF\xD8\xFF")
    image = EF_DG2[im_start:]

    return image


def show_result(result):
    if result:
        image = cv2.imread("images/checkmark.png")
    else:
        image = cv2.imread("images/xmark.png")
    cv2.putText(
        image,
        "Press [Q] to quit, anything else to continue",
        (50, 50),
        cv2.FONT_HERSHEY_PLAIN,
        1.2,
        (0, 0, 0),
        2,
        cv2.LINE_4,
    )
    cv2.imshow("Result", image)

    if cv2.waitKey(0) & 0xFF == ord("q"):
        cv2.destroyAllWindows()
        exit(0)
    cv2.destroyAllWindows()
    return

#!/usr/bin/env python3
"""This module does comparison of two images"""

import argparse
import os
from io import BytesIO

import numpy as np
from PIL import Image

import face_recognition


def compare_faces(id_image, cam_image, save_dest=False):
    im1 = bytes_to_np(id_image)
    im2 = cam_image[:, :, ::-1]
    # im2 = bytes_to_np(cam_image)

    id_face_loc = face_recognition.face_locations(im1)
    face_encodings = face_recognition.face_encodings(im1, id_face_loc, 10, "large")[0]

    cam_face_loc = face_recognition.face_locations(im2)
    face_encodings2 = face_recognition.face_encodings(im2, cam_face_loc, 10, "large")[0]

    if save_dest:
        i = 1
        while os.path.exists(f"files/face_one_{i}.jpeg"):
            i += 1
        j = 1
        while os.path.exists(f"files/face_two_{j}.jpeg"):
            j += 1
        Image.fromarray(im1).save(f"files/face_one_{i}.jpeg")
        Image.fromarray(im2).save(f"files/face_two_{j}.jpeg")

    # result = face_recognition.compare_faces([face_encodings], face_encodings2)
    dist = face_recognition.face_distance([face_encodings], face_encodings2)[0]
    if dist < 0.5:
        print(
            f"[+] Distance between the images is {dist}\nThese images are of the same people!"
        )
        return True
    else:
        print(
            f"[+] Distance between the images is {dist}\nThese images are of two different people!"
        )
        return False


def bytes_to_np(img):
    im = Image.open(BytesIO(img))
    im = im.convert("RGB")
    return np.array(im)


def jpeg_to_png(img):
    im = Image.open(BytesIO(img))
    width = 240
    height = int(im.size[1] * (240 / im.size[0]))
    im = im.convert("RGB").resize((width, height))
    stream = BytesIO()
    im.save(stream, format="PNG")
    return stream.getvalue()


"""with open("files/image_(3).jpeg", 'rb') as infile:
    image1 = infile.read()
with open("files/image_(2).jpeg", 'rb') as infile:
    image2 = infile.read()

compare_faces(image1, image2, "files")"""


def main(im1, im2):
    im1 = np.array(Image.open(im1).convert("RGB"))
    im2 = np.array(Image.open(im2).convert("RGB"))

    id_face_loc = face_recognition.face_locations(im1)
    face_encodings = face_recognition.face_encodings(im1, id_face_loc, 10, "large")[0]

    cam_face_loc = face_recognition.face_locations(im2)
    face_encodings2 = face_recognition.face_encodings(im2, cam_face_loc, 10, "large")[0]

    dist = face_recognition.face_distance([face_encodings], face_encodings2)[0]
    if dist < 0.5:
        print(f"[+] These images belong to the same person! ({dist})")
    else:
        print(f"[-] These images do not belong to the same person! ({dist})")


if __name__ == "__main__":

    def raise_(ex):
        """https://stackoverflow.com/a/8294654/6077951"""
        raise ex

    parser = argparse.ArgumentParser(
        description="Find if two images are of the same people."
    )
    parser.add_argument(
        "image_one",
        type=lambda x: x if os.path.isfile(x) else raise_(FileNotFoundError(x)),
        help="Path to image one",
    )
    parser.add_argument(
        "image_two",
        type=lambda x: x if os.path.isfile(x) else raise_(FileNotFoundError(x)),
        help="Path to image two",
    )
    args = parser.parse_args()

    main(args.image_one, args.image_two)
# Biometric Access Control System Using ID Card

The proposed solution is a two-factor physical authentication system (something you have, something you are).

The first factor is an authentic ID card, and the second factor is a biometric factor using a facial scan.

The first factor is verified using the ICAO e-passport applet available in Estonian residence permit cards. Cryptographic checks are performed according to ICAO Doc 9303 specification<sup>1</sup> to verify the integrity of the biometric data stored in the card and the authenticity of the document.

The second factor is verified by downloading the cardholder's facial image from the ID card and using face recognition technology to compare it to the picture taken from the webcam.

This feature is currently implemented only on the Estonian residence permit cards (issued to non-EU residents), but starting July 2021<sup>2</sup> will also be available on other types of Estonian ID cards.

The proposed solution can be used on the entrances to buildings or self-checkout machines where strong identity verification is needed. In such cases, if biometric authentication is necessary it needs to be supervised. In cases where biometric verification is not necessary, just the first factor can be used.

<img src="https://www.politsei.ee/thumbs/1800x1800r/Dokumentide%20naeidised/elamisloakaart2018/elamisloakaart-2018-esikuelg.jpg" height="200" alt="front side of Estonian residence permit"> <img src="https://www.politsei.ee/thumbs/1800x1800r/Dokumentide%20naeidised/elamisloakaart2018/elamisloakaart-2018-tagakuelg.jpg?c3509c0c85" height="200" alt="back side of Estonian residence permit">

<sup>1</sup>https://www.icao.int/publications/pages/publication.aspx?docnum=9303  
<sup>2</sup>https://www.ria.ee/sites/default/files/content-editors/ria_aastaraamat_2020_48lk_eng.pdf


## In action

![a demo of the program](../demo/demo.gif)
<sub>The image shown on the phone is taken from https://thispersondoesnotexist.com/</sub>


## Requirements
* Linux computer with python3.6 and above
* Contact smart card reader
* Webcam
* Estonian residence permit card (issued since December 2018)
* Internet connection to update CRLs and perform document online validity check

## Dependencies
### On Debian/Ubuntu:
First, [enable the universe repository](https://help.ubuntu.com/community/Repositories/Ubuntu).
Then download the necessary packages:
```shell
sudo apt-get install git wget build-essential cmake python3-dev python3-venv swig libpcsclite-dev pcscd
```
### On Arch Linux/Manjaro:
Download the necessary packages and enable the smart card service:
```shell
sudo pacman -S git wget python base-devel cmake swig ccid opensc
sudo systemctl enable --now pcscd.service
```

## Installation
```shell
git clone --recurse-submodules https://github.com/Fethbita/id_card_face_access.git
cd id_card_face_access
# Create virtualenv named '.venv'
python3 -m venv .venv
# Activate virtualenv
source .venv/bin/activate
# Upgrade pip
pip3 install --upgrade pip
# This last command is memory intensive because dlib is being built.
# Make sure you have available ram before attempting this command
pip3 install -r requirements.txt
```

## Running

Before running, make sure you activate the virtual environment with
```shell
source .venv/bin/activate
```
You can run the main program by running the module
```shell
python3 -m id_card_face_access
```
You can run individual modules, for example `face_compare.py` with
```shell
python3 -m id_card_face_access.face_compare path_to_image_one path_to_image_two
```

## Usage
```
usage: __main__.py [-h] [-online]

Biometric (Facial) Access Control System Using ID Card

optional arguments:
  -h, --help  show this help message and exit
  -online     Download crl and csca certificates online.
```

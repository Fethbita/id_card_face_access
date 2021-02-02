#!/usr/bin/env python3
"""The entry point for id_card_face_access"""

import argparse
import os
import subprocess
from multiprocessing.pool import ThreadPool

import PySimpleGUI as sg

from id_card_face_access.gui import setup_gui, reset_gui, window_update
from id_card_face_access.card_comms import send, wait_for_card
from id_card_face_access.mrz import estonia_read_mrz
from id_card_face_access.bac import establish_session_keys, read_data_from_ef
from id_card_face_access.file_operations import parse_efcom, get_dg_numbers, assert_dg_hash
from id_card_face_access.passive_authentication import passive_auth
from id_card_face_access.active_authentication import active_auth
from id_card_face_access.image_operations import get_jpeg_im
from id_card_face_access.camera import capture_image
from id_card_face_access.face_compare import compare_faces, jpeg_to_png
from id_card_face_access.ee_valid import check_validity

EVERYTHING_IS_OKAY = True

def main(args, first_run):
    """main function"""

    layout = setup_gui()

    window = sg.Window('ID Card Face Access', layout, return_keyboard_events=True, use_default_focus=False)

    while True:
        global EVERYTHING_IS_OKAY
        EVERYTHING_IS_OKAY = True
        ## GUI ##
        window_update(window)
        ## GUI ##

        CSCA_certs_dir = "EE_certs/csca_certs"
        crls_dir = "EE_certs/crls"

        if (args.online and first_run) or (
            not os.path.isdir(CSCA_certs_dir) or not os.path.isdir(crls_dir)
        ):
            ## GUI ##
            window['text_download_csca_crl'].update("Downloading CSCA certificates and CRLs...")
            window_update(window)
            ## GUI ##
            print("[+] Downloading CSCA certs and CRLs.")
            caca_address = "https://pki.politsei.ee/"
            csca_certs_links = [
                "csca_Estonia_2007.cer",
                "csca_Estonia_2009.crt",
                "csca_Estonia_2012.cer",
                "csca_Estonia_2015.cer",
                "csca_Estonia_2016.cer",
                "csca_Estonia_2019.cer",
                "csca_Estonia_2020.der",
            ]

            # Get the crl
            subprocess.run(
                ["wget", "-N", "-P", crls_dir, caca_address + "csca.crl"],
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
            )
            # Get csca certificates
            for link in csca_certs_links:
                subprocess.run(
                    ["wget", "-N", "-P", CSCA_certs_dir, caca_address + link],
                    stderr=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                )
            ## GUI ##
            window['text_download_csca_crl_status'].update("OK", text_color="green")
            window_update(window)
            ## GUI ##
        


        ## GUI ##
        window['text_card_insert'].update("Waiting for an ID card...")
        window_update(window)
        ## GUI ##
        
        # this will wait for card inserted in any reader
        # In a different thread so that the process doesn't block the GUI
        pool = ThreadPool(processes=1)
        async_result = pool.apply_async(wait_for_card)
        while True:
            event, values = window.read(timeout=20)

            if event == 'Exit' or event == sg.WIN_CLOSED:
                exit(0)
            if async_result.ready():
                channel = async_result.get()
                break
        ## GUI ##
        window['text_card_insert_status'].update("OK", text_color="green")
        window_update(window)
        ## GUI ##

        ## GUI ##
        window['text_read_info'].update("Reading data from the ID card...")
        window_update(window)
        ## GUI ##
        mrz_information, document_number, personal_id_code, name, surname = estonia_read_mrz(channel)
        ## GUI ##
        window['text_name_surname'].update(f"NAME: {name} {surname}")
        window['text_personal_code'].update(f"PERSONAL ID CODE: {personal_id_code}")
        window['text_doc_num'].update(f"DOCUMENT NUMBER: {document_number}")
        window_update(window)
        ## GUI ##

        # Select eMRTD application
        print("[+] Selecting LDS DF AID: A0000002471001...")
        aid = bytes.fromhex("A0000002471001")
        send(channel, [0x00, 0xA4, 0x04, 0x0C, len(aid)] + list(aid) + [0x00])

        ks_enc, ks_mac, SSC = establish_session_keys(channel, mrz_information)

        ## GUI ##
        window['text_read_info_status'].update("OK", text_color="green")
        window_update(window)
        ## GUI ##

        ## SECURE MESSAGING ##

        # Create "files" folder if it doesn't exist
        os.makedirs(os.path.dirname("files/"), exist_ok=True)

        ## GUI ##
        window['text_authentic'].update("Verifying authenticity of the ID card...")
        window_update(window)
        ## GUI ##

        # Read EF.COM
        SSC, EFCOM = read_data_from_ef(channel, ks_enc, ks_mac, SSC, b"\x01\x1E", "EF.COM")
        ef_com_dg_list = parse_efcom(EFCOM)

        # Read EF.SOD
        SSC, EFSOD = read_data_from_ef(channel, ks_enc, ks_mac, SSC, b"\x01\x1D", "EF.SOD")

        hash_alg, data_group_hash_values, error = passive_auth(EFSOD, CSCA_certs_dir, crls_dir, window, dump=False)
        if error:
            EVERYTHING_IS_OKAY = False
            ## GUI ##
            window['text_authentic_status'].update("ERROR", text_color="red")
            window_update(window)
            ## GUI ##

        ef_sod_dg_list = get_dg_numbers(data_group_hash_values)

        if ef_com_dg_list != ef_sod_dg_list:
            EVERYTHING_IS_OKAY = False
            print(
                "[-] EF.COM might have been changed, there are differences between EF_COM DGs and EF_SOD DGs!\n"
            )
            #reply = input("[?] Do you still want to proceed? [y/N] ")
            #if reply.lower() != "y":
            #    raise ValueError("[-] Potentially tampered document, DGs do not match!")
            ## GUI ##
            window['text_instruction'].update("Potentially tampered document! Check logs! [Enter] to continue [Escape] to stop.", text_color="red")
            ## GUI ##
            window['text_authentic_status'].update("ERROR", text_color="red")
            window_update(window)
            ## GUI ##
            ## GUI ##
            while True:
                event, values = window.read(timeout=20)

                if event == 'Exit' or event == sg.WIN_CLOSED:
                    exit(0)
                elif event.startswith("Return"):
                    break
                elif event.startswith("Escape"):
                    exit(1)
        elif not error:
            ## GUI ##
            window['text_authentic_status'].update("OK", text_color="green")
            window_update(window)
            ## GUI ##

        ## GUI ##
        window['text_valid'].update("Performing online document validity check...")
        window_update(window)
        ## GUI ##

        if check_validity(document_number):
            ## GUI ##
            window['text_valid_status'].update("OK", text_color="green")
            window_update(window)
            ## GUI ##
        else:
            EVERYTHING_IS_OKAY = False
            ## GUI ##
            window['text_valid_status'].update("ERROR", text_color="red")
            window_update(window)
            ## GUI ##

        if b"\x0f" in ef_sod_dg_list:
            # read EF.DG15 from the card
            # In a different thread so that the process doesn't block the GUI
            pool = ThreadPool(processes=1)
            async_result = pool.apply_async(read_data_from_ef, (channel, ks_enc, ks_mac, SSC, b"\x01" + b"\x0f", "EF.DG15"))
            while True:
                event, values = window.read(timeout=20)

                if event == 'Exit' or event == sg.WIN_CLOSED:
                    exit(0)
                if async_result.ready():
                    SSC, DG = async_result.get()
                    break

            assert_dg_hash(DG, data_group_hash_values, hash_alg, b"\x0f", window)

            SSC = active_auth(DG, channel, ks_enc, ks_mac, SSC, window)
            # print("[!] Active authentication is still not implemented!")

        for dg, dgname in ef_sod_dg_list.items():
            if dg == b"\x0f":
                # Active Authentication assumed completed
                continue

            if dg == b"\x03" or dg == b"\x04":
                # Sensitive Data: Finger and iris image data stored in the LDS
                # Data Groups 3 and 4, respectively. These data are considered
                # to be more privacy sensitive than data stored in the other
                # Data Groups.
                continue

            if dg == b"\x02":
                ## GUI ##
                window['text_read_image'].update("Reading facial image from the ID card...")
                window_update(window)
                ## GUI ##

            # read file from the card
            # In a different thread so that the process doesn't block the GUI
            pool = ThreadPool(processes=1)
            async_result = pool.apply_async(read_data_from_ef, (channel, ks_enc, ks_mac, SSC, b"\x01" + dg, dgname))
            while True:
                event, values = window.read(timeout=20)

                if event == 'Exit' or event == sg.WIN_CLOSED:
                    exit(0)
                if async_result.ready():
                    SSC, DG = async_result.get()
                    break

            assert_dg_hash(DG, data_group_hash_values, hash_alg, dg, window)

            if dg == b"\x02":
                id_image = get_jpeg_im(DG)
                ## GUI ##
                window['id_image'].update(data=jpeg_to_png(id_image))
                window['text_read_image_status'].update("OK", text_color="green")
                window_update(window)
                ## GUI ##

        print("[?] Please take a picture.")
        camera_image = capture_image(window)


        ## GUI ##
        window['text_face_compare'].update("Performing face comparison...")
        window_update(window)
        ## GUI ##
        # Compare faces
        # In a different thread so that the process doesn't block the GUI
        pool = ThreadPool(processes=1)
        async_result = pool.apply_async(compare_faces, (id_image, camera_image, False))
        while True:
            event, values = window.read(timeout=20)

            if event == 'Exit' or event == sg.WIN_CLOSED:
                exit(0)
            if async_result.ready():
                comparison_result = async_result.get()
                break

        if comparison_result:
            ## GUI ##
            window['text_face_compare_status'].update("SUCCESS", text_color="green")
            window_update(window)
            ## GUI ##
        else:
            ## GUI ##
            EVERYTHING_IS_OKAY = False
            window['text_face_compare_status'].update("FAILED", text_color="red")
            window_update(window)
            ## GUI ##
        
        if EVERYTHING_IS_OKAY:
            ## GUI ##
            window['result'].update("ACCESS GRANTED", text_color="green")
            window_update(window)
            ## GUI ##
        else:
            ## GUI ##
            window['result'].update("ACCESS DENIED", text_color="red")
            window_update(window)
            ## GUI ##
            

        ## GUI ##
        window['text_instruction'].update("Please take your ID card out and press [Enter] to run again.", text_color="white")
        window_update(window)
        ## GUI ##

        while True:
            event, values = window.read(timeout=20)

            if event == 'Exit' or event == sg.WIN_CLOSED:
                exit(0)
            elif event.startswith("Return"):
                reset_gui(window)
                channel.disconnect()
                break


def parse_arguments():
    """parse arguments"""
    parser = argparse.ArgumentParser(
        description="Biometric (Facial) Access Control System Using ID Card"
    )
    parser.add_argument(
        "-online",
        action="store_true",
        help="Download crl and csca certificates online.",
    )
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    arguments = parse_arguments()
    first_run = True
    while True:
        main(arguments, first_run)
        first_run = False

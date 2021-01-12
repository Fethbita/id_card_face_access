#!/usr/bin/env python3
"""This module captures an image from the camera"""

import cv2
import PySimpleGUI as sg
import face_recognition

def capture_image(window):
    cap = cv2.VideoCapture(-1)

    run = True
    while run:
        event, values = window.read(timeout=20)

        _, frame = cap.read()


        frame_show = frame.copy()
        width = 320
        height = int(frame_show.shape[0] * (320 / frame_show.shape[1]))
        frame_show = cv2.resize(frame_show, (width, height))

        rgb_small_frame = frame_show[:, :, ::-1]
        face_locations = face_recognition.face_locations(rgb_small_frame)
        for (top, right, bottom, left) in face_locations:
            cv2.rectangle(frame_show, (left, top), (right, bottom), (0, 255, 0), 2)


        imgbytes = cv2.imencode('.png', frame_show)[1].tobytes()
        ## GUI ##
        window['camera_image'].update(data=imgbytes)
        window['text_instruction'].update("Press [Enter] to capture image", text_color="white")
        ## GUI ##
        if event == 'Exit' or event == sg.WIN_CLOSED:
            exit(0)

        elif event.startswith("Return") and len(face_locations) > 1:
            window['text_instruction'].update("Multiple faces detected. Press [Enter] to try again", text_color="white")
            while True:
                event, values = window.read(timeout=20)

                if event == 'Exit' or event == sg.WIN_CLOSED:
                    exit(0)
                elif event.startswith("Return"):
                    break
        elif event.startswith("Return") and len(face_locations) < 1:
            window['text_instruction'].update("No faces detected. Press [Enter] to try again", text_color="white")
            while True:
                event, values = window.read(timeout=20)

                if event == 'Exit' or event == sg.WIN_CLOSED:
                    exit(0)
                elif event.startswith("Return"):
                    break
        elif event.startswith("Return") and len(face_locations) == 1:

            window['text_instruction'].update("Press [Enter] to accept image, [Escape] to try again", text_color="white")
            while True:
                event, values = window.read(timeout=20)

                if event == 'Exit' or event == sg.WIN_CLOSED:
                    exit(0)
                elif event.startswith("Return"):
                    window['text_instruction'].update("", text_color="white")
                    event, values = window.read(timeout=20)
                    run = False
                    break
                elif event.startswith("Escape"):
                    break

    return frame
import PySimpleGUI as sg

def setup_gui():
    sg.theme('DarkTeal10')

    ts = (40, 1)
    status_ts = (12, 1)
    text =[[sg.Text('', size=ts, justification='left', font='Helvetica 15', key='text_download_csca_crl'),
             sg.Text('', size=status_ts, justification='right', font='Helvetica 15', key='text_download_csca_crl_status')],
           [sg.Text('', size=ts, justification='left', font='Helvetica 15', key='text_card_insert'), 
             sg.Text('', size=status_ts, justification='right', font='Helvetica 15', key='text_card_insert_status')],
           [sg.Text('', size=ts, justification='left', font='Helvetica 15', key='text_read_info'),
             sg.Text('', size=status_ts, justification='right', font='Helvetica 15', key='text_read_info_status')],
           [sg.Text('', size=ts, justification='left', font='Helvetica 15', key='text_authentic'),
             sg.Text('', size=status_ts, justification='right', font='Helvetica 15', key='text_authentic_status')],
           [sg.Text('', size=ts, justification='left', font='Helvetica 15', key='text_valid'),
             sg.Text('', size=status_ts, justification='right', font='Helvetica 15', key='text_valid_status')],
           [sg.Text('', size=ts, justification='left', font='Helvetica 15', key='text_read_image'),
             sg.Text('', size=status_ts, justification='right', font='Helvetica 15', key='text_read_image_status')],
           [sg.Text('', size=ts, justification='left', font='Helvetica 15', key='text_face_compare'),
             sg.Text('', size=status_ts, justification='right', font='Helvetica 15', key='text_face_compare_status')],
           [sg.Text('', size=ts, font='Helvetica 15')],
           [sg.Text('', size=ts, justification='center', font='Helvetica 15', key='result')]]

    id_image = sg.Image(size=(240,320), key='id_image')
    camera_image = sg.Image(size=(320,240), key='camera_image')
    layout = [[sg.Text('', size=(85,1), justification='center', font='Helvetica 15', key='text_instruction')],
              [sg.Text('NAME: ', size=(35,1), justification='left', font='Helvetica 10', key='text_name_surname')],
              [sg.Text('PERSONAL ID CODE: ', size=(35,1), justification='left', font='Helvetica 10', key='text_personal_code')],
              [sg.Text('DOCUMENT NUMBER: ', size=(35,1), justification='left', font='Helvetica 10', key='text_doc_num')],
              [id_image, camera_image, sg.Frame(layout=text, title='')],
              [sg.Button('Exit', size=(10, 1), font='Helvetica 14')]]

    return layout

def reset_gui(window):
    window['text_download_csca_crl'].update("")
    window['text_download_csca_crl_status'].update("")
    window['text_card_insert'].update("")
    window['text_card_insert_status'].update("")
    window['text_read_info'].update("")
    window['text_read_info_status'].update("")
    window['text_authentic'].update("")
    window['text_authentic_status'].update("")
    window['text_valid'].update("")
    window['text_valid_status'].update("")
    window['text_read_image'].update("")
    window['text_read_image_status'].update("")
    window['text_face_compare'].update("")
    window['text_face_compare_status'].update("")
    window['result'].update("")
    window['text_instruction'].update("", text_color="white")
    window['text_name_surname'].update("NAME: ")
    window['text_personal_code'].update("PERSONAL ID CODE: ")
    window['text_doc_num'].update("DOCUMENT NUMBER: ")
    window['id_image'].update(filename='', size=(240,320))
    window['camera_image'].update(filename='', size=(320,240))




def window_update(window):
    event, values = window.read(timeout=20)
    if event == 'Exit' or event == sg.WIN_CLOSED:
        exit(0)
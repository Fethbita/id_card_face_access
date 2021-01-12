from urllib import request

def check_validity(doc_num):
    page = request.urlopen("https://www2.politsei.ee/qr/?qr=" + doc_num).read().decode("utf8")
    if f"The document {doc_num} is valid." in page:
        return True
    elif f"The document {doc_num} is invalid." in page:
        return False
    return False
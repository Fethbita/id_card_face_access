import os
import hashlib
import hmac

from OpenSSL.crypto import (
    verify,
    load_certificate,
    load_crl,
    FILETYPE_ASN1,
    FILETYPE_PEM,
    X509Store,
    X509StoreFlags,
    X509StoreContext,
    X509StoreContextError,
)
import PySimpleGUI as sg


from id_card_face_access.asn1 import dump_asn1, encode_oid_string, get_digestalg_name
from id_card_face_access.gui import window_update
from asn1_tiny_decoder.source.data.asn1tinydecoder import (
    asn1_node_root,
    asn1_get_all,
    asn1_get_value,
    asn1_get_value_of_type,
    asn1_node_next,
    asn1_node_first_child,
)


def passive_auth(EFSOD, CSCA_certs_dir, crls_dir, window, dump=False):
    error = False
    # get root node
    i = asn1_node_root(EFSOD)
    # unpack application data 0x77
    i = asn1_node_first_child(EFSOD, i)
    # unpack sequence
    i = asn1_node_first_child(EFSOD, i)
    # print id-signedData OBJECT IDENTIFIER
    if dump:
        print(dump_asn1(asn1_get_all(EFSOD, i)))
    # get 2nd item inside (SignedData EXPLICIT tagged)
    i = asn1_node_next(EFSOD, i)
    # unpack SignedData EXPLICIT tag
    i = asn1_node_first_child(EFSOD, i)
    # get 1st item inside (CMSVersion Value = v3)
    i = asn1_node_first_child(EFSOD, i)
    # get 2nd item (DigestAlgorithmIdentifiers) collection of message digest algorithm identifiers.
    # There MAY be any number of elements in the collection, including zero.
    i = asn1_node_next(EFSOD, i)
    # get 3rd item (EncapsulatedContentInfo) (LDS Document Security Object)
    i = asn1_node_next(EFSOD, i)

    # get 1st item inside (eContentType) (OID joint-iso-itu-t (2) international(23) icao(136) mrtd(1) security(1) ldsSecurityObject(1))
    j = asn1_node_first_child(EFSOD, i)
    eContentType = asn1_get_all(EFSOD, j)
    # get the EXPLICIT tagged encoded contents of ldsSecurityObject
    j = asn1_node_next(EFSOD, j)
    # get the encoded contents of ldsSecurityObject
    j = asn1_node_first_child(EFSOD, j)
    # print the value of eContent hash
    encapsulatedContent = asn1_get_value_of_type(EFSOD, j, "OCTET STRING")
    del j

    signerInfos, certificates, crls = None, None, None
    while signerInfos is None:
        # https://stackoverflow.com/a/52041365/6077951
        # get 4th item
        i = asn1_node_next(EFSOD, i)
        if EFSOD[i[0]] == 0xA0:
            # Constructed, Context-Specific 0
            certificates = i
            print("[+] CertificateSet exist")
        elif EFSOD[i[0]] == 0xA1:
            # Constructed, Context-Specific 1
            crls = i
            print("[+] Crls exist")
        else:
            signerInfos = i

    # The inspection system SHALL build and validate a certification path
    # from a Trust Anchor to the Document Signer Certificate used to
    # sign the Document Security Object (SOD) according to Doc 9303-12.

    # Add CA certificates to the store
    store = X509Store()

    # https://www2.politsei.ee/en/nouanded/isikut-toendavad-dokumendid/cert.dot
    print("[↳] Loading up CSCA certificates")
    CSCA_certs_dir = os.fsencode(CSCA_certs_dir)
    for file in os.listdir(CSCA_certs_dir):
        filename = os.fsdecode(file)
        with open(os.path.join(CSCA_certs_dir, file), "rb") as infile:
            cert = infile.read()
            if cert.startswith(b"-----BEGIN CERTIFICATE-----"):
                CSCA = load_certificate(FILETYPE_PEM, cert)
                store.add_cert(CSCA)
            else:
                CSCA = load_certificate(FILETYPE_ASN1, cert)
                store.add_cert(CSCA)
            print("\t[+] Loaded certificate:", filename)

    print("[↳] Loading up CRLs")
    for file in os.listdir(crls_dir):
        filename = os.fsdecode(file)
        with open(os.path.join(crls_dir, file), "rb") as infile:
            if filename.endswith(".crl"):
                CRL = load_crl(FILETYPE_ASN1, infile.read())
                store.add_crl(CRL)
            print("\t[+] Loaded CRL:", filename)

    store.set_flags(X509StoreFlags.CRL_CHECK_ALL)

    if certificates is not None:
        CDS = load_certificate(FILETYPE_ASN1, asn1_get_value(EFSOD, certificates))
        store_ctx = X509StoreContext(store, CDS)
        try:
            if store_ctx.verify_certificate() is None:
                print("[+] Document Signer Certificate is signed by a CSCA certificate")
        except X509StoreContextError as ex:
            error = True
            from id_card_face_access.__main__ import EVERYTHING_IS_OKAY
            EVERYTHING_IS_OKAY = False
            print(
                "[-] Document Signer Certificate is not signed by a CSCA certificate or is invalid!\n"
                + str(ex.args)
            )
            #reply = input("[?] Do you still want to proceed? [Y/n] ")
            #if reply.lower() != "y":
            #    raise ValueError(
            #        "[-] Document Signer Certificate is not signed by a CSCA certificate or is invalid!"
            #    ) from ex
            ## GUI ##
            window['text_instruction'].update("Error on document! Check logs! [Enter] to continue [Escape] to stop.", text_color="red")
            window_update(window)
            ## GUI ##
            while True:
                event, values = window.read(timeout=20)

                if event == 'Exit' or event == sg.WIN_CLOSED:
                    exit(0)
                elif event.startswith("Return"):
                    break
                elif event.startswith("Escape"):
                    exit(1)

    else:
        raise TypeError(
            "[-] This application doesn't support this kind of document yet!"
        )

    # get 1st signerInfo inside signerInfos
    i = asn1_node_first_child(EFSOD, signerInfos)
    # get 1st item inside 1st signerInfo (CMSVersion)
    i = asn1_node_first_child(EFSOD, i)
    signerInfo_ver = int.from_bytes(
        asn1_get_value_of_type(EFSOD, i, "INTEGER"), byteorder="big"
    )

    issuerAndSerialNumber, subjectKeyIdentifier = None, None
    # get 2nd item inside 1st signerInfo (SignerIdentifier)
    i = asn1_node_next(EFSOD, i)
    if signerInfo_ver == 1:
        issuerAndSerialNumber = i
    elif signerInfo_ver == 3:
        subjectKeyIdentifier = i

    if dump:
        print(
            dump_asn1(
                asn1_get_all(EFSOD, issuerAndSerialNumber or subjectKeyIdentifier)
            )
        )

    # get 3rd item inside 1st signerInfo (DigestAlgorithmIdentifier)
    i = asn1_node_next(EFSOD, i)
    # get hash algorithm used for encapsulatedContent and SignedAttrs
    hash_alg = asn1_get_all(EFSOD, asn1_node_first_child(EFSOD, i))
    hash_alg = get_digestalg_name(hash_alg)

    # get 4th item inside 1st signerInfo ([0] IMPLICIT SignedAttributes)
    i = asn1_node_next(EFSOD, i)
    # use EXPLICIT SET OF tag, rather than of the IMPLICIT [0] tag
    signedAttrs = asn1_get_all(EFSOD, i)
    signedAttrs = b"\x31" + signedAttrs[1:]

    # get the first Attribute from SignedAttributes
    j = asn1_node_first_child(EFSOD, i)
    contentType, signedAttrs_hash = None, None
    while contentType is None or signedAttrs_hash is None:
        # get the content-type and the message-digest
        k = asn1_node_first_child(EFSOD, j)
        # contentType
        if asn1_get_all(EFSOD, k) == encode_oid_string("1.2.840.113549.1.9.3"):
            # then the content-type attribute value MUST match the SignedData encapContentInfo eContentType value.
            k = asn1_node_next(EFSOD, k)
            k = asn1_node_first_child(EFSOD, k)
            contentType = asn1_get_all(EFSOD, k)
        # messageDigest
        elif asn1_get_all(EFSOD, k) == encode_oid_string("1.2.840.113549.1.9.4"):
            k = asn1_node_next(EFSOD, k)
            k = asn1_node_first_child(EFSOD, k)
            signedAttrs_hash = asn1_get_value_of_type(EFSOD, k, "OCTET STRING")
        j = asn1_node_next(EFSOD, j)
    del k, j

    hash_object = hashlib.new(hash_alg)
    hash_object.update(encapsulatedContent)
    eContent_hash = hash_object.digest()
    del hash_object
    #print("[+] Calculated hash of eContent =", eContent_hash.hex())
    #print("[+] Hash of eContent in SignedAttributes =", signedAttrs_hash.hex())

    if eContentType == contentType:
        print(
            "[+] Content Type of eContent match with the Content Type in SignedAttributes"
        )
    else:
        raise ValueError(
            "[-] Content Type of eContent DOES NOT match with the Content Type in SignedAttributes."
        )

    if hmac.compare_digest(signedAttrs_hash, eContent_hash):
        print("[+] Hash of eContent match with the hash in SignedAttributes")
    else:
        raise ValueError(
            "[+] Hash of eContent DOES NOT match with the hash in SignedAttributes."
        )

    # get 4th item inside 1st signerInfo (SignatureAlgorithmIdentifier)
    i = asn1_node_next(EFSOD, i)
    # get 5th item inside 1st signerInfo (SignatureValue)
    i = asn1_node_next(EFSOD, i)
    signature = asn1_get_value_of_type(EFSOD, i, "OCTET STRING")

    # Verify the signature with DS_cert using hash_alg
    if verify(CDS, signature, signedAttrs, hash_alg) is None:
        print("[+] The signature on EF_SOD is valid.")
    else:
        raise ValueError("[-] The signature on EF_SOD is not valid.")

    i = asn1_node_root(encapsulatedContent)
    i = asn1_node_first_child(encapsulatedContent, i)
    i = asn1_node_next(encapsulatedContent, i)
    i = asn1_node_next(encapsulatedContent, i)

    dataGroupHashValues = asn1_get_all(encapsulatedContent, i)

    return hash_alg, dataGroupHashValues, error
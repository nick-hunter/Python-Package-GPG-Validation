import requests
import json
import tempfile
import gnupg
from datetime import datetime
from config import *

gpg = gnupg.GPG(gnupghome=GPG_home)
gpg.encoding = 'utf-8'

def download(url, version="?"):
    result = {}
    packageTemp = tempfile.NamedTemporaryFile()
    sigTemp = tempfile.NamedTemporaryFile()
    r = requests.get(url, allow_redirects=True)
    if(r.status_code == 200):
        packageTemp.write(r.content)
        sig_url = url + ".asc"

        r = requests.get(sig_url, allow_redirects=True)
        if(r.status_code == 200):
            sigTemp.write(r.content)

            stream = open(sigTemp.name, "rb")
            sigTemp.seek(0) #Seek to start of file

            verified = gpg.verify_file(stream, packageTemp.name)

            if verified.trust_level is not None and verified.trust_level >= verified.TRUST_FULLY:
                result['trust_text'] = verified.trust_text

            result['version'] = version
            result['verified_status'] = verified.status
            result['key_id'] = verified.key_id
            ts = int(verified.timestamp)
            result['timestamp'] = datetime.utcfromtimestamp(ts).strftime('%m-%d-%Y %H:%M:%S')

        else:
            result['error'] = "error downloading signature"

        packageTemp.close()
        sigTemp.close()
    else:
        result['error'] = "error downloading package"
    return result

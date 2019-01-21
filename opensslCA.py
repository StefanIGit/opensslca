/*
Webbased CA for Testing
2018 Stefan.Schmidt@knallakoff.de 
*/

from flask import Flask
from flask import jsonify
from flask import send_file
from flask import request
from flask import render_template
from random import randint
import time
from OpenSSL import crypto
import inspect, os


# stuff one must change
sPassPhrase = 'ToSecretPasswordPhraseThing123456780#~~[$'
sCAKeyFilename = 'rootCA.key'
sCACertFilename = 'rootCA.pem'



TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA
path = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))) # script directory
 
app = Flask(__name__)

with open(path + '/' + sCAKeyFilename, 'r') as fp:
    lines = fp.readlines()

caKey = ''
for item in lines:
        caKey +=item
        
with open(path + '/' + sCACertFilename, 'r') as fp:
    lines = fp.readlines()

caCert = ''
for item in lines:
        caCert +=item

def createCertificate(req, (issuerCert, issuerKey), serial, (notBefore, notAfter), digest="sha256"):
    """
    Generate a certificate given a certificate request.
    Arguments: req        - Certificate reqeust to use
               issuerCert - The certificate of the issuer
               issuerKey  - The private key of the issuer
               serial     - Serial number for the certificate
               notBefore  - Timestamp (relative to now) when the certificate
                            starts being valid
               notAfter   - Timestamp (relative to now) when the certificate
                            stops being valid
               digest     - Digest method to use for signing, default is md5
    Returns:   The signed certificate in an X509 object
    """
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(issuerKey, digest)
    return cert


def decode_crt(crt):
     cert = crypto.X509()

        
@app.route('/',methods=['POST','GET'])
def usage():
    
    if request.method == 'POST':
        if 'CSR' in request.form:
            csr = request.form['CSR']
            serial = randint(1, 5000001)
            if 'validfrom' in request.form:
                notBefore = int(request.form['validfrom'])
            else:
                notBefore = -60*60*24
            if 'validuntil' in request.form:
                notAfter = int(request.form['validuntil'])
            else:
                notAfter = 60*60*24*4
            issuerCert = crypto.load_certificate(crypto.FILETYPE_PEM, caCert)
            issuerKey = crypto.load_privatekey(crypto.FILETYPE_PEM, caKey, sPassPhrase)
            req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
            
            cert = createCertificate(req,(issuerCert, issuerKey), serial, (notBefore, notAfter), digest="sha256")
            return render_template('usage.html', caCert=caCert, CSR=csr, cert=crypto.dump_certificate(crypto.FILETYPE_PEM, cert), TabToLoad='CRTTAB')

        elif 'crttodecode' in request.form:
            decoded = crypto.load_certificate(crypto.FILETYPE_PEM, request.form['crttodecode'])
            subject = decoded.get_subject()
            components = dict(subject.get_components())
            retVal = "Common name: "+ components['CN'] +'\n'
            retVal += "Organisation: " + components['O'] +'\n'
            retVal += "Orgainistional unit "+ components['OU'] +'\n'
            retVal += "City/locality: "+ components['L'] +'\n'
            retVal += "State/province: "+  components['ST'] +'\n'
            retVal += "Country: " + components['C'] +'\n'
            retVal += "From: " + time.strftime('%Y-%m-%d %H:%M:%S' , time.strptime(decoded.get_notBefore(), '%Y%m%d%H%M%SZ')) +'\n'
            retVal += "Until: " +  time.strftime('%Y-%m-%d %H:%M:%S' , time.strptime(decoded.get_notAfter(), '%Y%m%d%H%M%SZ')) +'\n'
            #retVal += "Issuer: "+ decoded.get_issuer()
            return render_template('usage.html', crttodecode=retVal, TabToLoad='DECRTTAB')
        else:
            return 'hmm no!'
    else:
        return render_template('usage.html', caCert=caCert, TabToLoad='CATAB')


if __name__ == '__main__':
    app.run(debug=False,host="0.0.0.0")


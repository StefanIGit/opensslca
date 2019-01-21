# opensslca
CA web page to testing

This is a little web page to sign CSRs with variable "Valid from" and "Valid until".
It can decode CRT too, not CSR...
and it is python based

I use it to for testing.

Oh you need crate your own CA crt and change theses in opensslCA.py

- sPassPhrase = 'ToSecretPasswordPhraseThing123456780#\~~\[$'
- sCAKeyFilename = 'rootCA.key'
- sCACertFilename = 'rootCA.pem'

The *opensslca.service* file is a systemd unit file ?!? the thing you need to run it these days as a service on linux. 

Not tested on windows :) 

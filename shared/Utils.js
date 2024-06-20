const forge = require('node-forge');

// Gera um par de chaves RSA
function generateKeyPair() {
  const keyPair = forge.pki.rsa.generateKeyPair(2048);
  return keyPair;
}

// Cria um certificado autoassinado
function selfSignCertificate(keyPair) {
  const cert = forge.pki.createCertificate();
  cert.publicKey = keyPair.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

  const attrs = [
    { name: 'commonName', value: 'example.org' },
    { name: 'countryName', value: 'US' },
    { shortName: 'ST', value: 'Virginia' },
    { name: 'localityName', value: 'Blacksburg' },
    { name: 'organizationName', value: 'Test' },
    { shortName: 'OU', value: 'Test' }
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, digitalSignature: true, nonRepudiation: true, keyEncipherment: true, dataEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true, clientAuth: true, codeSigning: true, emailProtection: true, timeStamping: true },
    { name: 'nsCertType', client: true, server: true, email: true, objsign: true, sslCA: true, emailCA: true, objCA: true },
    { name: 'subjectAltName', altNames: [{ type: 6, value: 'http://example.org/webid#me' }] },
    { name: 'subjectKeyIdentifier' }
  ]);

  cert.sign(keyPair.privateKey, forge.md.sha256.create());
  return cert;
}

module.exports = { generateKeyPair, selfSignCertificate };

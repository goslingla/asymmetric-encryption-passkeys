const fs = require('fs');
const forge = require('node-forge');
const { generateKeyPair, selfSignCertificate } = require('../shared/Utils');

class PasskeyGenerator {
  constructor() {
    this.keyStore = {};
  }

  generatePasskey(alias, password) {
    if (fs.existsSync(`${alias}.p12`)) {
      console.log('A chave já existe. Pulando a geração.');
      return;
    }

    // Gera um par de chaves RSA
    const keyPair = generateKeyPair();

    // Cria um certificado autoassinado
    const cert = selfSignCertificate(keyPair);

    // Armazena a chave privada no keystore
    this.keyStore[alias] = keyPair.privateKey;

    // Converte as chaves e certificado para o formato PKCS12
    const p12Asn1 = forge.pkcs12.toPkcs12Asn1(keyPair.privateKey, [cert], password);
    const p12Der = forge.asn1.toDer(p12Asn1).getBytes();

    // Salva o arquivo .p12 no disco
    fs.writeFileSync(`${alias}.p12`, p12Der, { encoding: 'binary' });

    console.log('Chave gerada e armazenada no keystore.');
  }
}

const passkeyGenerator = new PasskeyGenerator();
const alias = 'clientPasskey';
const password = 'password';

// Gera a passkey
passkeyGenerator.generatePasskey(alias, password);

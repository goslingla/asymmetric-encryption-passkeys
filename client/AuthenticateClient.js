const fs = require('fs');
const forge = require('node-forge');
const axios = require('axios');

class Client {
  constructor() {
    this.keyStore = {};
  }

  authenticate(alias, password, challenge) {
    // Lê o arquivo .p12 do disco
    const p12Der = fs.readFileSync(`${alias}.p12`, { encoding: 'binary' });
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

    // Extrai o certificado do arquivo .p12
    const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
    const certificate = certBags[forge.pki.oids.certBag][0].cert;
    const publicKey = certificate.publicKey;

    // Criptografa o desafio usando a chave pública
    const encrypted = publicKey.encrypt(forge.util.encodeUtf8(challenge), 'RSA-OAEP', {
      md: forge.md.sha256.create(),
      mgf1: forge.mgf.mgf1.create(forge.md.sha1.create())
    });

    // Retorna a resposta criptografada em base64
    return forge.util.encode64(encrypted);
  }

  async sendAuthentication(email) {
    const alias = 'clientPasskey';
    const password = 'password';

    try {
      // Solicita um desafio do servidor
      const challengeResponse = await axios.post('http://localhost:3000/request-challenge', { email });
      const challenge = challengeResponse.data.challenge;

      // Autentica usando o desafio recebido
      const response = this.authenticate(alias, password, challenge);

      // Envia a resposta de autenticação para o servidor
      const serverResponse = await axios.post('http://localhost:3000/authenticate', {
        challenge: challenge,
        response: response
      });

      console.log('Resposta do servidor:', serverResponse.data);
    } catch (error) {
      console.error('Erro ao autenticar com o servidor:', error);
    }
  }
}

const client = new Client();
const email = 'user@example.com';

// Envia a autenticação para o servidor
client.sendAuthentication(email);

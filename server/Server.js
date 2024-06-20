const fs = require('fs');
const express = require('express');
const forge = require('node-forge');
const { selfSignCertificate } = require('../shared/Utils');

class Server {
  constructor() {
    // Lê o arquivo .p12 gerado pelo cliente
    const p12Der = fs.readFileSync('../client/clientPasskey.p12', { encoding: 'binary' });
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, 'password');

    // Extrai a chave privada do keystore
    const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
    this.privateKey = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0].key;

    // Inicializa o servidor Express
    this.app = express();
    this.app.use(express.json()); // Middleware para parsear JSON
    this.setupRoutes(); // Configura as rotas do servidor
  }

  setupRoutes() {
    // Rota para solicitar um desafio (challenge)
    this.app.post('/request-challenge', (req, res) => {
      const email = req.body.email; // Obtém o email do corpo da requisição
      const challenge = forge.util.encode64(forge.random.getBytesSync(32)); // Gera um desafio aleatório
      console.log(`Desafio gerado para o email ${email}: ${challenge}`);
      res.json({ challenge }); // Retorna o desafio ao cliente
    });

    // Rota para autenticação
    this.app.post('/authenticate', (req, res) => {
      const { challenge, response } = req.body; // Obtém o desafio e a resposta do corpo da requisição
      const isValid = this.validateAuthentication(challenge, response); // Valida a autenticação
      if (isValid) {
        console.log(`Autenticação bem-sucedida para o desafio: ${challenge}`);
      } else {
        console.log(`Falha na autenticação para o desafio: ${challenge}`);
      }
      res.json({ success: isValid }); // Retorna o resultado da autenticação ao cliente
    });
  }

  validateAuthentication(challenge, response) {
    try {
      const decodedResponse = forge.util.decode64(response); // Decodifica a resposta base64
      const decrypted = this.privateKey.decrypt(decodedResponse, 'RSA-OAEP', {
        md: forge.md.sha256.create(), // Utiliza SHA-256 como função de hash
        mgf1: forge.mgf.mgf1.create(forge.md.sha1.create()) // Utiliza SHA-1 para MGF1
      });
      // Compara o desafio descriptografado com o original
      return decrypted === forge.util.encodeUtf8(challenge);
    } catch (error) {
      console.error('Erro ao validar a autenticação:', error);
      return false;
    }
  }

  start(port = 3000) {
    // Inicia o servidor na porta especificada
    this.app.listen(port, () => {
      console.log(`Servidor ouvindo na porta ${port}`);
    });
  }
}

const server = new Server();
server.start();

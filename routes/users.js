const crypto = require('crypto');
const Forge = require('node-forge');
const fs = require('fs');
const path = require('path');
Forge.options.usePureJavaScript = false;

const express = require('express');
const router = express.Router();

const getCaCertificate = async () => {
  const caCertPem = await fs.readFileSync(
    path.resolve(__dirname, `../certificate/ca-cert.pem`)
  );

  const caPrivatePem = await fs.readFileSync(
    path.resolve(__dirname, `../certificate/ca-private.pem`)
  );

  return {
    certificate: caCertPem.toString(),
    privateKey: caPrivatePem.toString(),
  };
};

/* GET users listing. */
router.get('/verify/pk12', async function (req, res, next) {
  try {
    console.log('11111111111111')
    const { rsa } = Forge.pki;
    // get CA certificate and private key
    const generateCA = await getCaCertificate();
    const caPrivateKey = Forge.pki.privateKeyFromPem(generateCA.privateKey);
    // read file from base64 encode because it is saved by base64 encode
    const getCertP12 = await fs.readFileSync(
      path.resolve(__dirname, `../certificate/reseller.p12`),"base64"
    );
    const p12Der = Forge.util.decode64(getCertP12);

    const p12Asn1 = Forge.asn1.fromDer(p12Der);
    const password = 'password'
    // const password = 'b05t2hxo'
    const certificatepkcs12 = Forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

    console.log('p12================', certificatepkcs12);

    const bags = certificatepkcs12.getBags({bagType: Forge.pki.oids.certBag});

    const keyBags =  certificatepkcs12.getBags({ bagType: Forge.pki.oids.keyBag});
    var keys = keyBags[Forge.pki.oids.keyBag][0];
    // bags are key'd by attribute type (here "friendlyName")
    // and the key values are an array of matching objects
    var cert = bags[Forge.pki.oids.certBag][0];
    console.log('  22222222222222222  keys   ',keys)

    // console.log('  22222222222222222  cert subject   ',cert.cert.subject)

    // console.log('  22222222222222222  cert public key   ',cert.cert.publicKey.n.toString())

    const caCert = Forge.pki.certificateFromPem(generateCA.certificate);
    const caStore = Forge.pki.createCaStore([caCert]);
    // convert pem format to certificate

    try {
      const result = Forge.pki.verifyCertificateChain(caStore, [cert.cert]);
      console.log('result========', result);
    } catch (error) {
      console.log('errororo========', error);
    }

    res.json({
      "test": "test"
    });

  } catch (err) {
    console.log('=====', err);
  }

});

module.exports = router;

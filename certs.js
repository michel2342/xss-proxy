import forge from "node-forge";

const { pki, md } = forge;

let caKey;
let caCert;
const hostCerts = new Map();

export function generateCA() {
  const keys = pki.rsa.generateKeyPair(2048);
  const cert = pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(
    cert.validity.notAfter.getFullYear() + 10,
  );

  const attrs = [{ name: "commonName", value: "xss-proxy CA" }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: "basicConstraints", cA: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true },
  ]);
  cert.sign(keys.privateKey, md.sha256.create());

  caKey = keys.privateKey;
  caCert = cert;

  return {
    cert: pki.certificateToPem(cert),
    key: pki.privateKeyToPem(keys.privateKey),
  };
}

export function getHostCert(hostname) {
  if (hostCerts.has(hostname)) {
    return hostCerts.get(hostname);
  }

  const keys = pki.rsa.generateKeyPair(2048);
  const cert = pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = Date.now().toString(16);
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(
    cert.validity.notAfter.getFullYear() + 1,
  );

  cert.setSubject([{ name: "commonName", value: hostname }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    {
      name: "subjectAltName",
      altNames: [{ type: 2, value: hostname }],
    },
  ]);
  cert.sign(caKey, md.sha256.create());

  const result = {
    cert: pki.certificateToPem(cert),
    key: pki.privateKeyToPem(keys.privateKey),
  };
  hostCerts.set(hostname, result);
  return result;
}

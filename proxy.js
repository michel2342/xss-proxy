import tls from "node:tls";
import { getHostCert } from "./certs.js";

const HOP_BY_HOP = new Set([
  "transfer-encoding",
  "connection",
  "keep-alive",
  "proxy-connection",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "upgrade",
]);

function parseHttpRequest(buffer, defaultHost) {
  const str = buffer.toString("utf8");
  const headerEnd = str.indexOf("\r\n\r\n");
  if (headerEnd === -1) {
    return null;
  }

  const headerBytes = headerEnd + 4;
  const headerPart = str.slice(0, headerEnd);
  const lines = headerPart.split("\r\n");
  const [method, reqPath] = lines[0].split(" ");

  const headers = {};
  let contentLength = 0;
  for (let i = 1; i < lines.length; i++) {
    const colonIdx = lines[i].indexOf(":");
    if (colonIdx === -1) continue;
    const name = lines[i].slice(0, colonIdx);
    const value = lines[i].slice(colonIdx + 1).trim();
    if (HOP_BY_HOP.has(name.toLowerCase())) continue;
    headers[name] = value;
    if (name.toLowerCase() === "content-length") {
      contentLength = parseInt(value, 10);
    }
  }

  if (buffer.length < headerBytes + contentLength) {
    return null;
  }

  const bodyBuf = buffer.subarray(headerBytes, headerBytes + contentLength);
  const consumed = headerBytes + contentLength;
  const host = headers["Host"] || headers["host"] || defaultHost;
  const url = `https://${host}${reqPath}`;

  return { request: { method, url, headers, body: bodyBuf.toString("hex") }, consumed };
}

function writeHttpResponse(socket, response) {
  if (response.error) {
    socket.write("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
    return;
  }

  const { status, statusText, headers, body } = response;
  const bodyBuf = Buffer.from(body, "hex");

  let head = `HTTP/1.1 ${status} ${statusText}\r\n`;
  for (const [name, value] of headers) {
    if (HOP_BY_HOP.has(name.toLowerCase())) continue;
    if (name.toLowerCase() === "content-length") continue;
    head += `${name}: ${value}\r\n`;
  }
  head += `Content-Length: ${bodyBuf.length}\r\n`;
  head += "\r\n";

  socket.write(head);
  socket.write(bodyBuf);
}

export function handleHttpProxy(req, res, forwardRequest) {
  const chunks = [];
  req.on("data", (chunk) => chunks.push(chunk));
  req.on("end", () => {
    const body = Buffer.concat(chunks).toString("hex");
    const headers = {};
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const name = req.rawHeaders[i];
      if (HOP_BY_HOP.has(name.toLowerCase())) continue;
      headers[name] = req.rawHeaders[i + 1];
    }

    forwardRequest({ url: req.url, method: req.method, headers, body }, (response) => {
      if (response.error) {
        res.writeHead(502, { "Content-Type": "text/plain" });
        res.end(response.error);
        return;
      }

      const { status, headers: respHeaders, body: respBody } = response;
      const headerObj = {};
      for (const [name, value] of respHeaders) {
        if (HOP_BY_HOP.has(name.toLowerCase())) continue;
        headerObj[name] = value;
      }
      res.writeHead(status, headerObj);
      res.end(Buffer.from(respBody, "hex"));
    });
  });
}

export function handleConnect(req, clientSocket, _head, forwardRequest) {
  const [hostname] = req.url.split(":");

  clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");

  const hostCert = getHostCert(hostname);
  const tlsSocket = new tls.TLSSocket(clientSocket, {
    isServer: true,
    key: hostCert.key,
    cert: hostCert.cert,
  });

  let buffer = Buffer.alloc(0);
  let processing = false;

  function processBuffer() {
    if (processing) return;

    const result = parseHttpRequest(buffer, hostname);
    if (!result) return;

    processing = true;
    buffer = buffer.subarray(result.consumed);

    forwardRequest(result.request, (response) => {
      writeHttpResponse(tlsSocket, response);
      processing = false;
      if (buffer.length > 0) processBuffer();
    });
  }

  tlsSocket.on("data", (data) => {
    buffer = Buffer.concat([buffer, data]);
    processBuffer();
  });

  tlsSocket.on("error", (err) => {
    console.error(`[mitm] ${hostname}: ${err.message}`);
  });
}

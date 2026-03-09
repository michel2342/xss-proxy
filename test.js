import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import crypto from "node:crypto";
import { WebSocket } from "ws";
import { generateCA, getHostCert } from "./certs.js";

const PROXY_PORT = 9100;
const TARGET_HTTP_PORT = 9101;
const TARGET_HTTPS_PORT = 9102;

let proxyProcess;
let targetHttpServer;
let targetHttpsServer;
let passed = 0;
let failed = 0;

function assert(condition, msg) {
  if (!condition) {
    failed++;
    console.error(`  FAIL: ${msg}`);
  } else {
    passed++;
    console.log(`  PASS: ${msg}`);
  }
}

// A simple target HTTP server the victim "browser" will fetch from
function startTargetHttpServer() {
  return new Promise((resolve) => {
    targetHttpServer = http.createServer((req, res) => {
      if (req.method === "POST") {
        const chunks = [];
        req.on("data", (c) => chunks.push(c));
        req.on("end", () => {
          const body = Buffer.concat(chunks).toString();
          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end(`echo:${body}`);
        });
        return;
      }
      res.writeHead(200, {
        "Content-Type": "text/plain",
        "X-Custom": "test-header",
      });
      res.end("hello from target");
    });
    targetHttpServer.listen(TARGET_HTTP_PORT, resolve);
  });
}

// A simple target HTTPS server for CONNECT/MITM testing
function startTargetHttpsServer() {
  return new Promise((resolve) => {
    const ca = generateCA();
    const hostCert = getHostCert("localhost");

    targetHttpsServer = https.createServer(
      { key: hostCert.key, cert: hostCert.cert },
      (req, res) => {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end("hello from https target");
      },
    );
    targetHttpsServer.listen(TARGET_HTTPS_PORT, resolve);
  });
}

// Start the proxy server as a child process
async function startProxy() {
  const { fork } = await import("node:child_process");
  return new Promise((resolve, reject) => {
    proxyProcess = fork("server.js", ["--port", String(PROXY_PORT)], {
      cwd: "/opt/xss-proxy",
      silent: true,
    });

    let output = "";
    proxyProcess.stdout.on("data", (data) => {
      output += data.toString();
      if (output.includes("Waiting for victim")) {
        resolve();
      }
    });
    proxyProcess.stderr.on("data", (data) => {
      output += data.toString();
    });
    proxyProcess.on("error", reject);

    setTimeout(() => reject(new Error(`Proxy did not start: ${output}`)), 5000);
  });
}

// Simulate a victim browser: connects via WebSocket, handles requests
function connectVictim() {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://localhost:${PROXY_PORT}/ws`);

    ws.on("open", () => resolve(ws));
    ws.on("error", reject);

    ws.on("message", async (data) => {
      const msg = JSON.parse(data.toString());
      if (msg.type !== "request") return;

      const { id, url, method, headers, body } = msg;

      try {
        const fetchHeaders = {};
        for (const name of Object.keys(headers)) {
          fetchHeaders[name] = headers[name];
        }

        // Use Node http.request instead of fetch to avoid TLS issues
        // in test (we're simulating what a browser fetch() would do)
        const parsedUrl = new URL(url);
        const reqOpts = {
          hostname: parsedUrl.hostname,
          port: parsedUrl.port,
          path: parsedUrl.pathname + parsedUrl.search,
          method,
          headers: fetchHeaders,
        };

        const transport = parsedUrl.protocol === "https:" ? https : http;
        if (parsedUrl.protocol === "https:") {
          reqOpts.rejectUnauthorized = false;
        }

        const proxyReq = transport.request(reqOpts, (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            const respBody = Buffer.concat(chunks).toString("hex");
            const respHeaders = [];
            for (let i = 0; i < res.rawHeaders.length; i += 2) {
              respHeaders.push([res.rawHeaders[i], res.rawHeaders[i + 1]]);
            }
            ws.send(
              JSON.stringify({
                type: "response",
                id,
                response: {
                  status: res.statusCode,
                  statusText: res.statusMessage,
                  headers: respHeaders,
                  body: respBody,
                },
              }),
            );
          });
        });

        if (method !== "GET" && method !== "HEAD" && body) {
          proxyReq.write(Buffer.from(body, "hex"));
        }
        proxyReq.end();
      } catch (err) {
        ws.send(JSON.stringify({ type: "response", id, error: err.message }));
      }
    });
  });
}

// Send an HTTP proxy request through the proxy
function proxyGet(targetUrl) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: "localhost",
        port: PROXY_PORT,
        path: targetUrl,
        method: "GET",
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString(),
          });
        });
      },
    );
    req.on("error", reject);
    req.end();
  });
}

// Send an HTTP proxy POST request
function proxyPost(targetUrl, postBody) {
  return new Promise((resolve, reject) => {
    const bodyBuf = Buffer.from(postBody);
    const req = http.request(
      {
        hostname: "localhost",
        port: PROXY_PORT,
        path: targetUrl,
        method: "POST",
        headers: { "Content-Length": bodyBuf.length },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          resolve({
            status: res.statusCode,
            body: Buffer.concat(chunks).toString(),
          });
        });
      },
    );
    req.on("error", reject);
    req.write(bodyBuf);
    req.end();
  });
}

// Test CONNECT method (HTTPS MITM proxy)
function proxyConnect(hostname, port, path) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: "localhost",
      port: PROXY_PORT,
      method: "CONNECT",
      path: `${hostname}:${port}`,
    });

    req.on("connect", (_res, socket) => {
      const tlsSocket = tls.connect(
        { socket, servername: hostname, rejectUnauthorized: false },
        () => {
          const httpReq =
            `GET ${path} HTTP/1.1\r\nHost: ${hostname}:${port}\r\n\r\n`;
          tlsSocket.write(httpReq);

          let data = Buffer.alloc(0);
          let headersParsed = false;
          let contentLength = 0;
          let headerLen = 0;
          let statusCode = 0;

          tlsSocket.on("data", (chunk) => {
            data = Buffer.concat([data, chunk]);

            if (!headersParsed) {
              const str = data.toString();
              const idx = str.indexOf("\r\n\r\n");
              if (idx === -1) return;
              headersParsed = true;
              headerLen = idx + 4;
              const headStr = str.slice(0, idx);
              statusCode = parseInt(headStr.split("\r\n")[0].split(" ")[1], 10);
              const clMatch = headStr.match(/content-length:\s*(\d+)/i);
              contentLength = clMatch ? parseInt(clMatch[1], 10) : 0;
            }

            if (data.length >= headerLen + contentLength) {
              const body = data.subarray(headerLen, headerLen + contentLength).toString();
              tlsSocket.destroy();
              resolve({ status: statusCode, body });
            }
          });
        },
      );
      tlsSocket.on("error", reject);
    });

    req.on("error", reject);
    req.end();
  });
}

// Test: proxy returns 502 when no victim is connected
async function testNoVictim() {
  console.log("\n[Test] Proxy without victim connected");
  const res = await proxyGet(
    `http://localhost:${TARGET_HTTP_PORT}/`,
  );
  assert(res.status === 502, `Returns 502 (got ${res.status})`);
  assert(
    res.body.includes("No victim"),
    `Error mentions no victim (got "${res.body}")`,
  );
}

// Test: GET request forwarded through victim
async function testHttpGet() {
  console.log("\n[Test] HTTP GET through proxy");
  const res = await proxyGet(
    `http://localhost:${TARGET_HTTP_PORT}/`,
  );
  assert(res.status === 200, `Status 200 (got ${res.status})`);
  assert(
    res.body === "hello from target",
    `Body matches (got "${res.body}")`,
  );
  assert(
    res.headers["x-custom"] === "test-header",
    `Custom header forwarded (got "${res.headers["x-custom"]}")`,
  );
}

// Test: POST request with body
async function testHttpPost() {
  console.log("\n[Test] HTTP POST through proxy");
  const res = await proxyPost(
    `http://localhost:${TARGET_HTTP_PORT}/`,
    "test-body-data",
  );
  assert(res.status === 200, `Status 200 (got ${res.status})`);
  assert(
    res.body === "echo:test-body-data",
    `POST body echoed (got "${res.body}")`,
  );
}

// Test: CONNECT method (HTTPS MITM)
async function testConnect() {
  console.log("\n[Test] CONNECT (HTTPS MITM) through proxy");
  const res = await proxyConnect("localhost", TARGET_HTTPS_PORT, "/");
  assert(res.status === 200, `Status 200 (got ${res.status})`);
  assert(
    res.body.includes("hello from https target"),
    `HTTPS body matches (got "${res.body}")`,
  );
}

// Test: /hook.js is served
async function testHookServed() {
  console.log("\n[Test] Hook script served");
  const res = await new Promise((resolve, reject) => {
    http.get(`http://localhost:${PROXY_PORT}/hook.js`, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString(),
        });
      });
    }).on("error", reject);
  });
  assert(res.status === 200, `Status 200 (got ${res.status})`);
  assert(
    res.headers["content-type"] === "application/javascript",
    `Content-Type is JS`,
  );
  assert(
    res.headers["access-control-allow-origin"] === "*",
    `CORS header set`,
  );
  assert(res.body.includes("WebSocket"), `Contains WebSocket code`);
}

// Test: /status endpoint
async function testStatus() {
  console.log("\n[Test] Status endpoint");
  const res = await new Promise((resolve, reject) => {
    http.get(`http://localhost:${PROXY_PORT}/status`, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        resolve({
          status: res.statusCode,
          body: JSON.parse(Buffer.concat(chunks).toString()),
        });
      });
    }).on("error", reject);
  });
  assert(res.status === 200, `Status 200`);
  assert(
    res.body.victim === true,
    `Reports victim connected (got ${res.body.victim})`,
  );
}

async function run() {
  try {
    console.log("Starting target servers...");
    await startTargetHttpServer();
    await startTargetHttpsServer();

    console.log("Starting proxy server...");
    await startProxy();

    // Test without victim first
    await testHookServed();
    await testNoVictim();

    // Connect victim
    console.log("\nConnecting simulated victim...");
    const victimWs = await connectVictim();
    // Give proxy a moment to register the connection
    await new Promise((r) => setTimeout(r, 200));

    await testStatus();
    await testHttpGet();
    await testHttpPost();
    await testConnect();

    victimWs.close();
  } catch (err) {
    console.error("Test error:", err);
    failed++;
  } finally {
    console.log(`\n${"=".repeat(40)}`);
    console.log(`Results: ${passed} passed, ${failed} failed`);
    console.log(`${"=".repeat(40)}`);

    if (proxyProcess) proxyProcess.kill();
    if (targetHttpServer) targetHttpServer.close();
    if (targetHttpsServer) targetHttpsServer.close();

    process.exit(failed > 0 ? 1 : 0);
  }
}

run();

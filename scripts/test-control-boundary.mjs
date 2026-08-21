import assert from "node:assert/strict";
import { networkInterfaces } from "node:os";
import net from "node:net";

const port = 8080;
assert.equal(process.geteuid?.(), 1000);
assert.throws(() => process.setuid(1001));
const destinations = new Set(["127.0.0.1"]);
for (const addresses of Object.values(networkInterfaces())) {
  for (const address of addresses ?? []) {
    if (address.family === "IPv4") destinations.add(address.address);
  }
}

async function connectionIsBlocked(host) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      resolve(true);
    }, 1_000);
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.destroy();
      reject(new Error(`Tool uid reached the Hand supervisor at ${host}:${port}`));
    });
    socket.once("error", () => {
      clearTimeout(timer);
      resolve(true);
    });
  });
}

for (const destination of destinations) {
  assert.equal(await connectionIsBlocked(destination), true);
}

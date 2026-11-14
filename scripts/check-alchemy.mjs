import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const envPath = path.resolve(__dirname, "../.env");

if (!fs.existsSync(envPath)) {
  console.error("Error: .env file not found at " + envPath);
  process.exit(1);
}

const envContent = fs.readFileSync(envPath, "utf8");
let apiKey = "";

for (const line of envContent.split("\n")) {
  const trimmed = line.trim();
  if (trimmed.startsWith("#") || !trimmed) continue;
  const eqIdx = trimmed.indexOf("=");
  if (eqIdx !== -1) {
    const key = trimmed.slice(0, eqIdx).trim();
    let val = trimmed.slice(eqIdx + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (key === "ALCHEMY_API_KEY") {
      apiKey = val;
      break;
    }
  }
}

if (!apiKey) {
  console.error("Error: ALCHEMY_API_KEY not found in .env");
  process.exit(1);
}

const targetAddress = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"; // vitalik.eth
const endpoint = `https://base-mainnet.g.alchemy.com/v2/${apiKey}`;

console.log(`Connecting to Alchemy Base endpoint: https://base-mainnet.g.alchemy.com/v2/${apiKey.slice(0, 4)}...${apiKey.slice(-4)}`);
console.log(`Target: vitalik.eth (${targetAddress})`);

const payload = {
  jsonrpc: "2.0",
  id: 1,
  method: "eth_getBalance",
  params: [targetAddress, "latest"],
};

try {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const text = await res.text();
    console.error(`HTTP Request failed with status ${res.status} ${res.statusText}`);
    console.error(`Response body: ${text}`);
    process.exit(1);
  }

  const data = await res.json();

  if (data.error) {
    console.error("RPC Error:", JSON.stringify(data.error, null, 2));
    process.exit(1);
  }

  const rawHex = data.result;
  const balanceWei = BigInt(rawHex);
  // Format to ETH (18 decimals)
  const divisor = 10n ** 18n;
  const integerPart = balanceWei / divisor;
  const fractionalPart = (balanceWei % divisor).toString().padStart(18, "0").slice(0, 6);
  const ethBalance = `${integerPart}.${fractionalPart}`;

  console.log("\n--- Alchemy API Call Successful ---");
  console.log(`Raw Hex Balance: ${rawHex}`);
  console.log(`Balance in Wei:   ${balanceWei.toString()} wei`);
  console.log(`Balance in ETH:   ${ethBalance} ETH on Base`);
} catch (err) {
  console.error("Network or unexpected error:", err.message || err);
  process.exit(1);
}


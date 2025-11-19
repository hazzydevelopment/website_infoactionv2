import core from "@actions/core";
import whois from "whois";
import util from "util";
import dns from "dns/promises";
import axios from "axios";
import { execSync } from "child_process";

const lookupWhois = util.promisify(whois.lookup);

function parseDomain(url) {
  try {
    if (/^https?:\/\//i.test(url)) return new URL(url).hostname.replace(/^www\./, "");
    return url.replace(/^www\./, "");
  } catch {
    return url.replace(/^www\./, "");
  }
}

async function sslExpiry(host) {
  try {
    const cmd = `echo | openssl s_client -servername ${host} -connect ${host}:443 2>/dev/null | openssl x509 -noout -dates`;
    const out = execSync(cmd).toString();
    const m = out.match(/notAfter=(.+)/);
    return m ? new Date(m[1]).toISOString() : null;
  } catch {
    return null;
  }
}

async function run() {
  try {
    const rawUrl = core.getInput("url");
    const domain = parseDomain(rawUrl);

    core.setOutput("domain", domain);

    // IP
    let ip = null;
    try {
      const res = await dns.lookup(domain);
      ip = res.address;
      core.setOutput("ip", ip);
    } catch {}

    // IP country
    if (ip) {
      try {
        const geo = await axios.get(`http://ip-api.com/json/${ip}`);
        core.setOutput("ip_country", geo.data.country || null);
      } catch {}
    }

    // SSL expiry
    const ssl = await sslExpiry(domain);
    if (ssl) core.setOutput("ssl_expires", ssl);

    // WHOIS basic
    try {
      const raw = await lookupWhois(domain);
      const registrarMatch = raw.match(/Registrar:\s*(.+)/i);
      core.setOutput("registrar", registrarMatch ? registrarMatch[1].trim() : null);
    } catch {}

    // tech hints
    const hints = [];
    try {
      const res = await axios.get(`https://${domain}`, { validateStatus: () => true });
      if (res.headers.server) hints.push(`server: ${res.headers.server}`);
      if (res.headers["x-powered-by"]) hints.push(`x-powered-by: ${res.headers["x-powered-by"]}`);
      if (res.data.includes("wp-content")) hints.push("Likely WordPress");
    } catch {}

    core.setOutput("tech_hints", JSON.stringify(hints));

  } catch (err) {
    core.setFailed(err.message);
  }
}

run();

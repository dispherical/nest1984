#!/usr/bin/env node
const { Command } = require('commander');
const program = new Command();
const { execSync } = require("child_process");
const pcap = require('pcap');

if (process.getuid() !== 0) console.error("You must run nest1984 as root.") || process.exit(1)

program
    .name('1984')
    .description('nest\'s watchbird')
    .version(require("./package.json").version);

program.command('ps')
    .description('Check process details and flag suspicious ones')
    .action(() => {
        const suspiciousPatterns = [
            /ss-server|ss-local/i,
            /openvpn|vpnkit/i,
            /java.*(?:minecraft-server|spigot|bukkit|paper|forge-server|craftbukkit).*\.jar|java.*-server.*minecraft|\.minecraft\/server\.jar/i,
            /\b(tor(\.real)?(\.exe)?|torsocks|obfs4proxy)\b/i, ,
            /proxychains|dante|redsocks|squid|sockscap|privoxy|redir/i,
            /nmap|masscan|zmap|unicornscan|scanrand|hping|scapy/i,
            /wireshark|tcpdump|ettercap|driftnet|arpspoof/i,
            /xmrig|cpuminer|ethminer|claymore|lolminer|t-rex|cryptonight|ethmine|cgminer|bfgminer|minerd|ethereum|monero|bitminer|nanopool/i,
            /nc\s+.*\s+-e\s+|netcat.*-e|\/dev\/tcp\/|bash\s+-i\s+>|\bncat\b.*\s+-e\s+|socat\s+.*exec:|python\s+-c\s+['"]import\s+socket/i,
            /linpeas|linEnum|pspy|unix-privesc-check|gtfobin|dirtycow/i,
            /metasploit|msfconsole|msfvenom|sqlmap|hydra|medusa|aircrack|wifite|recon-ng|beef-xss/i,
            /ssh\s+-(?:R|D|L)|autossh|sshuttle/i,
            /rkhunter|chkrootkit|unhide|rootkit|rookit-scanner/i,
            /darkcomet|blackshades|njrat|mirai|qbot|emotet|trickbot/i,
        ];

        try {
            const psOutput = execSync("ps aux", { encoding: "utf-8", maxBuffer: 1024 * 1024 * 100 }); // 100MB max (why is it so high? bc it can be!)
            const lines = psOutput.split("\n");
            if (!lines.length) console.info("✅ Nothing suspicious appears to be going on.")

            lines.forEach(line => {
                suspiciousPatterns.forEach(pattern => {
                    if (pattern.test(line)) {
                        const parts = line.trim().split(/\s+/);
                        const user = parts[0];
                        const pid = parts[1];
                        const command = parts.slice(10).join(" ");
                        const matchedPattern = pattern.toString();

                        console.warn(`User: ${user}\nPID: ${pid}\nCommand: ${command}\nMatched Pattern: ${matchedPattern}\n---\n`)
                    }
                });
            });
        } catch (e) {
        }
    });
    program.command('pcap')
    .description('Spins up a daemon to watch for symmetrical traffic')
    .action(() => {
        const trafficMap = new Map();
        const session = pcap.createSession('ens18', {
            filter: 'ip'
        });

        const WINDOW_MS = 5000;
        const SYMMETRY_THRESHOLD = 0.7;

        session.on('packet', function (rawPacket) {
            const packet = pcap.decode.packet(rawPacket);
            const ipLayer = packet.payload.payload;
            const src = ipLayer.saddr?.addr?.join('.');
            const dst = ipLayer.daddr?.addr?.join('.');
            const len = ipLayer.total_length;

            const isInbound = dst === "37.27.51.34"|| dst === "2a01:4f9:3081:399c::4";

            const userKey = src; 

            const record = trafficMap.get(userKey) || { inbound: 0, outbound: 0, lastUpdated: Date.now() };

            if (isInbound) record.inbound += len;
            else record.outbound += len;

            record.lastUpdated = Date.now();
            trafficMap.set(userKey, record);
        });

        setInterval(() => {
            const now = Date.now();
            for (const [key, { inbound, outbound, lastUpdated }] of trafficMap.entries()) {
                if (now - lastUpdated > WINDOW_MS) {
                    const total = inbound + outbound;
                    const ratio = Math.min(inbound, outbound) / Math.max(inbound, outbound);

                    if (total > 10 * 1024 * 1024 && ratio > SYMMETRY_THRESHOLD) {
                        console.log(`[!] Symmetrical traffic detected for ${key}: ${inbound} in / ${outbound} out`);
                    }

                    trafficMap.delete(key);
                }
            }
        }, 1000);

    });

program.parse();
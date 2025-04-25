#!/usr/bin/env bun
const { Command } = require('commander');
const program = new Command();
const { execSync } = require("child_process");

program
  .name('1984')
  .description('nest\'s watchbird')
  .version(require("./package.json").version);

program.command('ps')
  .description('Check process details and flag suspicious ones')
  .action((str, options) => {

    
    const suspiciousPatterns = [
        /ss-server|ss-local/i,
        /openvpn|vpnkit/i,
        /java.*(?:minecraft-server|spigot|bukkit|paper|forge-server|craftbukkit).*\.jar|java.*-server.*minecraft|\.minecraft\/server\.jar/i,
        /\b(tor(\.real)?(\.exe)?|torsocks|obfs4proxy)\b/i,,
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
    } catch(e){
    }
  });

program.parse();
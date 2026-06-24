const fs = require('fs');

function parsePcap(buffer, rules = []) {
    if (buffer.length < 24) throw new Error("Invalid PCAP file: too short");
    
    // Global Header
    const magicNumber = buffer.readUInt32LE(0);
    let isLittleEndian = true;
    if (magicNumber === 0xa1b2c3d4) {
        isLittleEndian = true;
    } else if (magicNumber === 0xd4c3b2a1) {
        isLittleEndian = false;
    } else {
        throw new Error("Invalid PCAP file: wrong magic number");
    }
    
    const readUInt32 = isLittleEndian ? (offset) => buffer.readUInt32LE(offset) : (offset) => buffer.readUInt32BE(offset);
    const readUInt16 = isLittleEndian ? (offset) => buffer.readUInt16LE(offset) : (offset) => buffer.readUInt16BE(offset);
    
    const network = readUInt32(20);
    if (network !== 1) { // 1 = Ethernet
        throw new Error("Only Ethernet link type is supported");
    }
    
    // Create output buffer with global header
    const outputChunks = [buffer.subarray(0, 24)];
    
    let offset = 24;
    let totalPackets = 0;
    let totalBytes = 0;
    let tcpPackets = 0;
    let udpPackets = 0;
    let forwarded = 0;
    let dropped = 0;
    
    const appCounts = {};
    const detectedSnis = new Map(); // SNI -> App
    
    // Simulating Load Balancers and Fast Path threads
    const numLbs = 2;
    const fpsPerLb = 2;
    const numFps = numLbs * fpsPerLb;
    const lbCounts = Array(numLbs).fill(0);
    const fpCounts = Array(numFps).fill(0);
    
    // Helper to map IP bytes to string
    function ipToString(ipBuf, start) {
        return `${ipBuf[start]}.${ipBuf[start+1]}.${ipBuf[start+2]}.${ipBuf[start+3]}`;
    }
    
    // Helper to parse rules
    const isIpBlocked = (ip) => rules.some(r => r.type === 'ip' && r.value === ip);
    const isAppBlocked = (app) => rules.some(r => r.type === 'app' && r.value.toLowerCase() === app.toLowerCase());
    const isDomainBlocked = (domain) => rules.some(r => r.type === 'domain' && domain.toLowerCase().includes(r.value.toLowerCase()));
    
    const appSignatures = [
        { name: "YouTube", patterns: ["youtube", "googlevideo", "ytimg"] },
        { name: "Facebook", patterns: ["facebook", "fbcdn"] },
        { name: "Google", patterns: ["google.com", "gstatic", "apis.google"] },
        { name: "GitHub", patterns: ["github", "githubusercontent"] },
        { name: "Spotify", patterns: ["spotify", "audio-ak-spotify"] },
        { name: "TikTok", patterns: ["tiktok", "byteoversea", "ibyteimg"] },
        { name: "Twitter/X", patterns: ["twitter", "twimg", "x.com", "netflix.com", "microsoft.com"] },
        { name: "Telegram", patterns: ["telegram", "telegram.org", "tdesktop"] },
        { name: "Zoom", patterns: ["zoom.us", "zoom.com"] },
        { name: "Discord", patterns: ["discord"] },
        { name: "Apple", patterns: ["apple.com", "icloud"] },
        { name: "Cloudflare", patterns: ["cloudflare"] },
        { name: "Amazon", patterns: ["amazon"] },
        { name: "Instagram", patterns: ["instagram", "cdninstagram"] }
    ];
    
    function sniToAppType(sni) {
        const lower = sni.toLowerCase();
        for (const sig of appSignatures) {
            for (const pat of sig.patterns) {
                if (lower.includes(pat)) return sig.name;
            }
        }
        return "HTTPS";
    }
    
    const flowStates = {}; // key -> flow
    
    while (offset + 16 <= buffer.length) {
        const tsSec = readUInt32(offset);
        const tsUsec = readUInt32(offset + 4);
        const inclLen = readUInt32(offset + 8);
        const origLen = readUInt32(offset + 12);
        
        if (offset + 16 + inclLen > buffer.length) break;
        
        const pktData = buffer.subarray(offset + 16, offset + 16 + inclLen);
        const pktHeader = buffer.subarray(offset, offset + 16);
        offset += 16 + inclLen;
        
        totalPackets++;
        totalBytes += inclLen;
        
        // Parse Ethernet Header
        if (inclLen < 14) continue;
        const etherType = pktData.readUInt16BE(12);
        if (etherType !== 0x0800) continue; // Only IPv4 supported in this demo C++ engine logic
        
        // Parse IPv4 Header
        const ipStart = 14;
        const ipIhl = pktData[ipStart] & 0x0f;
        const ipProto = pktData[ipStart + 9];
        const srcIp = ipToString(pktData, ipStart + 12);
        const destIp = ipToString(pktData, ipStart + 16);
        
        const hasTcp = ipProto === 6;
        const hasUdp = ipProto === 17;
        if (!hasTcp && !hasUdp) continue;
        
        if (hasTcp) tcpPackets++;
        if (hasUdp) udpPackets++;
        
        // Parse Ports
        const transportStart = ipStart + ipIhl * 4;
        if (pktData.length < transportStart + 4) continue;
        const srcPort = pktData.readUInt16BE(transportStart);
        const destPort = pktData.readUInt16BE(transportStart + 2);
        
        // Flow Key (mimic C++)
        const flowKey = `${srcIp}:${srcPort}->${destIp}:${destPort}:${ipProto}`;
        
        // Thread Workload Hashing Simulation
        let hash = 0;
        for (let i = 0; i < flowKey.length; i++) {
            hash = (hash * 31 + flowKey.charCodeAt(i)) >>> 0;
        }
        
        const lbIdx = hash % numLbs;
        const fpIdx = hash % numFps;
        lbCounts[lbIdx]++;
        fpCounts[fpIdx]++;
        
        // Flow state lookup
        if (!flowStates[flowKey]) {
            flowStates[flowKey] = {
                app: "Unknown",
                blocked: false,
                sni: ""
            };
        }
        const flow = flowStates[flowKey];
        
        let payloadOffset = transportStart;
        if (hasTcp) {
            const tcpOff = (pktData[transportStart + 12] >> 4) & 0x0f;
            payloadOffset += tcpOff * 4;
        } else {
            payloadOffset += 8;
        }
        
        const payloadLength = pktData.length - payloadOffset;
        
        // HTTPS SNI Extraction
        if (destPort === 443 && payloadLength > 5) {
            const payload = pktData.subarray(payloadOffset);
            if (payload[0] === 0x16 && payload[5] === 0x01) { // TLS Handshake + Client Hello
                let tlsOffset = 43; // Skip random, session id length
                if (tlsOffset < payload.length) {
                    const sessionLen = payload[tlsOffset];
                    tlsOffset += 1 + sessionLen;
                    
                    if (tlsOffset + 2 <= payload.length) {
                        const cipherLen = payload.readUInt16BE(tlsOffset);
                        tlsOffset += 2 + cipherLen;
                        
                        if (tlsOffset + 1 <= payload.length) {
                            const compLen = payload[tlsOffset];
                            tlsOffset += 1 + compLen;
                            
                            if (tlsOffset + 2 <= payload.length) {
                                const extLen = payload.readUInt16BE(tlsOffset);
                                tlsOffset += 2;
                                const extEnd = tlsOffset + extLen;
                                
                                while (tlsOffset + 4 <= extEnd && tlsOffset + 4 <= payload.length) {
                                    const extType = payload.readUInt16BE(tlsOffset);
                                    const extDataLen = payload.readUInt16BE(tlsOffset + 2);
                                    tlsOffset += 4;
                                    
                                    if (extType === 0x0000) { // SNI type
                                        if (tlsOffset + 5 <= payload.length) {
                                            const sniLen = payload.readUInt16BE(tlsOffset + 3);
                                            if (tlsOffset + 5 + sniLen <= payload.length) {
                                                const sni = payload.toString('ascii', tlsOffset + 5, tlsOffset + 5 + sniLen);
                                                flow.sni = sni;
                                                flow.app = sniToAppType(sni);
                                                detectedSnis.set(sni, flow.app);
                                            }
                                        }
                                        break;
                                    }
                                    tlsOffset += extDataLen;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // HTTP Host Extraction
        if (destPort === 80 && payloadLength > 10) {
            const payloadStr = pktData.toString('ascii', payloadOffset);
            const hostMatch = payloadStr.match(/Host:\s*([^\r\n]+)/i);
            if (hostMatch) {
                const host = hostMatch[1].trim();
                flow.sni = host;
                flow.app = sniToAppType(host);
                detectedSnis.set(host, flow.app);
            } else if (flow.app === "Unknown") {
                flow.app = "HTTP";
            }
        }
        
        // DNS, HTTPS, HTTP fallbacks
        if (flow.app === "Unknown") {
            if (destPort === 443 || srcPort === 443) flow.app = "HTTPS";
            else if (destPort === 80 || srcPort === 80) flow.app = "HTTP";
            else if (destPort === 53 || srcPort === 53) flow.app = "DNS";
        }
        
        // Rule checks
        if (!flow.blocked) {
            if (isIpBlocked(srcIp) || isIpBlocked(destIp)) flow.blocked = true;
            if (isAppBlocked(flow.app)) flow.blocked = true;
            if (flow.sni && isDomainBlocked(flow.sni)) flow.blocked = true;
        }
        
        // Stats and filter output packaging
        if (flow.blocked) {
            dropped++;
        } else {
            forwarded++;
            outputChunks.push(pktHeader);
            outputChunks.push(pktData);
        }
        
        appCounts[flow.app] = (appCounts[flow.app] || 0) + 1;
    }
    
    const sortedApps = Object.entries(appCounts)
        .map(([app, count]) => {
            const percentage = parseFloat(((count / totalPackets) * 100).toFixed(1));
            return {
                app,
                count,
                percentage,
                blocked: isAppBlocked(app)
            };
        })
        .sort((a, b) => b.count - a.count);
        
    const responseSnis = [];
    detectedSnis.forEach((app, domain) => {
        responseSnis.push({ domain, app });
    });
    
    const report = {
        totalPackets,
        totalBytes,
        tcpPackets,
        udpPackets,
        forwarded,
        dropped,
        threadStats: {
            lbs: lbCounts.map((count, id) => ({ id, count })),
            fps: fpCounts.map((count, id) => ({ id, count }))
        },
        appBreakdown: sortedApps,
        detectedSnis: responseSnis
    };
    
    return {
        report,
        filteredPcap: Buffer.concat(outputChunks)
    };
}

module.exports = { parsePcap };

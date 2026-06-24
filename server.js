const express = require('express');
const multer = require('multer');
const cors = require('cors');
const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Enable CORS and JSON parsing
app.use(cors());
app.use(express.json());

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Ensure upload and output directories exist
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// Set up multer for file upload
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// Keep track of output files for downloading
const outputFiles = new Map();

// Helper function to parse stdout reports from the DPI engine
function parseDpiReport(stdout) {
    const report = {
        totalPackets: 0,
        totalBytes: 0,
        tcpPackets: 0,
        udpPackets: 0,
        forwarded: 0,
        dropped: 0,
        threadStats: {
            lbs: [],
            fps: []
        },
        appBreakdown: [],
        detectedSnis: []
    };

    const lines = stdout.split('\n');

    // Parse simple KPIs
    for (const line of lines) {
        if (line.includes('Total Packets:')) {
            const match = line.match(/Total Packets:\s+(\d+)/);
            if (match) report.totalPackets = parseInt(match[1]);
        }
        if (line.includes('Total Bytes:')) {
            const match = line.match(/Total Bytes:\s+(\d+)/);
            if (match) report.totalBytes = parseInt(match[1]);
        }
        if (line.includes('TCP Packets:')) {
            const match = line.match(/TCP Packets:\s+(\d+)/);
            if (match) report.tcpPackets = parseInt(match[1]);
        }
        if (line.includes('UDP Packets:')) {
            const match = line.match(/UDP Packets:\s+(\d+)/);
            if (match) report.udpPackets = parseInt(match[1]);
        }
        if (line.includes('Forwarded:')) {
            const match = line.match(/Forwarded:\s+(\d+)/);
            if (match) report.forwarded = parseInt(match[1]);
        }
        if (line.includes('Dropped:')) {
            const match = line.match(/Dropped:\s+(\d+)/);
            if (match) report.dropped = parseInt(match[1]);
        }

        // Parse Thread Stats
        if (line.includes('LB') && line.includes('dispatched:')) {
            const match = line.match(/LB(\d+)\s+dispatched:\s+(\d+)/);
            if (match) report.threadStats.lbs.push({ id: parseInt(match[1]), count: parseInt(match[2]) });
        }
        if (line.includes('FP') && line.includes('processed:')) {
            const match = line.match(/FP(\d+)\s+processed:\s+(\d+)/);
            if (match) report.threadStats.fps.push({ id: parseInt(match[1]), count: parseInt(match[2]) });
        }

        // Parse SNI mappings: e.g. "  - www.youtube.com -> YouTube"
        if (line.trim().startsWith('- ') && line.includes('->')) {
            const parts = line.split('->');
            if (parts.length === 2) {
                report.detectedSnis.push({
                    domain: parts[0].replace('-', '').trim(),
                    app: parts[1].trim()
                });
            }
        }
    }

    // Parse Application Breakdown Table
    let inAppBreakdown = false;
    for (const line of lines) {
        if (line.includes('APPLICATION BREAKDOWN')) {
            inAppBreakdown = true;
            continue;
        }
        if (inAppBreakdown && (line.includes('╚════════════') || line.includes('╔════════════') || line.includes('[Detected'))) {
            inAppBreakdown = false;
            continue;
        }

        if (inAppBreakdown && line.startsWith('║') && !line.includes('APPLICATION BREAKDOWN')) {
            // Lines are like: ║ HTTPS                39  50.6% ##########            ║
            // Or: ║ YouTube               4   5.2% # (BLOCKED)                    ║
            const cleanLine = line.replace(/║/g, '').trim();
            if (cleanLine === '' || cleanLine.startsWith('---')) continue;

            const isBlocked = cleanLine.includes('(BLOCKED)');
            const lineWithoutBlockTag = cleanLine.replace('(BLOCKED)', '').trim();

            const tokens = lineWithoutBlockTag.split(/\s+/);
            if (tokens.length >= 3) {
                // First token: App name
                // Second: Count
                // Third: Percentage (e.g. 50.6%)
                const appName = tokens[0];
                const count = parseInt(tokens[1]);
                const percentage = parseFloat(tokens[2].replace('%', ''));
                
                report.appBreakdown.push({
                    app: appName,
                    count: count,
                    percentage: percentage,
                    blocked: isBlocked
                });
            }
        }
    }

    return report;
}

// POST endpoint for file analysis
app.post('/api/analyze', upload.single('pcap'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No PCAP file uploaded' });
    }

    const inputPath = req.file.path;
    const outputFilename = `output-${Date.now()}.pcap`;
    const outputPath = path.join(uploadDir, outputFilename);

    // Get rules from body
    let rules = [];
    try {
        if (req.body.rules) {
            rules = JSON.parse(req.body.rules);
        }
    } catch (e) {
        // Fallback if rules is already parsed object
        rules = req.body.rules || [];
    }

    // Build arguments
    const args = [inputPath, outputPath];
    for (const rule of rules) {
        if (rule.type === 'ip') {
            args.push('--block-ip', rule.value);
        } else if (rule.type === 'app') {
            args.push('--block-app', rule.value);
        } else if (rule.type === 'domain') {
            args.push('--block-domain', rule.value);
        }
    }

    // Execute the compiled C++ DPI engine
    const binaryPath = path.join(__dirname, 'dpi_engine');

    // Check if binary exists
    if (!fs.existsSync(binaryPath)) {
        // Try compiling it on the fly if it hasn't been compiled
        return res.status(500).json({ 
            error: 'DPI Engine binary not found. Run "npm run build" first.' 
        });
    }

    execFile(binaryPath, args, (error, stdout, stderr) => {
        // Clean up input file right away
        fs.unlink(inputPath, (err) => {
            if (err) console.error('Error deleting input file:', err);
        });

        if (error) {
            console.error('Execution error:', error, stderr);
            return res.status(500).json({ error: 'Failed to run packet analysis', details: stderr });
        }

        // Parse CLI report stdout
        const report = parseDpiReport(stdout);

        // Generate download token
        const fileToken = Math.random().toString(36).substring(2, 15);
        outputFiles.set(fileToken, outputPath);

        // Auto-delete output file after 10 minutes to save space
        setTimeout(() => {
            if (outputFiles.has(fileToken)) {
                fs.unlink(outputPath, (err) => {
                    if (err && err.code !== 'ENOENT') console.error('Error auto-deleting output file:', err);
                });
                outputFiles.delete(fileToken);
            }
        }, 10 * 60 * 1000);

        res.json({
            success: true,
            report: report,
            downloadToken: fileToken
        });
    });
});

// GET endpoint to download filtered file
app.get('/api/download', (req, res) => {
    const token = req.query.token;
    if (!token || !outputFiles.has(token)) {
        return res.status(404).send('Download expired or file not found.');
    }

    const filePath = outputFiles.get(token);
    res.download(filePath, 'filtered.pcap', (err) => {
        if (err) {
            console.error('Download error:', err);
        }
        // Delete the file after successful or failed download to save disk space
        fs.unlink(filePath, (unlinkErr) => {
            if (unlinkErr && unlinkErr.code !== 'ENOENT') console.error('Error deleting file after download:', unlinkErr);
        });
        outputFiles.delete(token);
    });
});

// Handle all other routing by serving frontend index.html
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Deep Packet Analyzer server is running on http://localhost:${PORT}`);
});

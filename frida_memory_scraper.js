// Frida Memory Scraper - Search ChatGPT process memory for text
console.log('[*] ChatGPT Memory Scraper Starting...');

const logFile = '/tmp/memory_scrape.txt';
const searchPatterns = [
    'MEMORYDUMP',
    'assistant',
    'Hello',
    "I'm",
    'response',
    'message'
];

console.log('[*] This script will scan process memory for text patterns');
console.log('[*] Send a message containing "MEMORYDUMP_12345" first!');
console.log('');

// Function to search memory regions
function scanMemory() {
    console.log('[*] Scanning process memory...');

    const ranges = Process.enumerateRanges('r--');
    let findings = [];

    for (let i = 0; i < Math.min(ranges.length, 100); i++) {
        const range = ranges[i];

        // Skip very large ranges (>100MB)
        if (range.size > 100 * 1024 * 1024) continue;

        try {
            // Read memory region
            const data = Memory.readByteArray(range.base, Math.min(range.size, 1024 * 1024));
            const view = new Uint8Array(data);

            // Convert to string
            let str = '';
            for (let j = 0; j < view.length; j++) {
                if (view[j] >= 32 && view[j] <= 126) {
                    str += String.fromCharCode(view[j]);
                } else if (str.length > 0) {
                    // Check if accumulated string contains our patterns
                    if (str.length > 20) {
                        for (const pattern of searchPatterns) {
                            if (str.includes(pattern)) {
                                const excerpt = str.substring(
                                    Math.max(0, str.indexOf(pattern) - 100),
                                    Math.min(str.length, str.indexOf(pattern) + 500)
                                );

                                findings.push({
                                    pattern: pattern,
                                    address: range.base.add(j - str.length),
                                    text: excerpt
                                });

                                console.log('\n[FOUND] Pattern:', pattern);
                                console.log('Address:', range.base.add(j - str.length));
                                console.log('Text:', excerpt.substring(0, 200));
                            }
                        }
                    }
                    str = '';
                }
            }
        } catch (e) {
            // Skip inaccessible regions
        }

        if (i % 10 === 0) {
            console.log(`[*] Scanned ${i}/${Math.min(ranges.length, 100)} regions...`);
        }
    }

    // Save findings
    if (findings.length > 0) {
        const file = new File(logFile, 'w');
        file.write('=== Memory Scrape Results ===\n\n');
        findings.forEach((f, idx) => {
            file.write(`\nFinding ${idx + 1}:\n`);
            file.write(`Pattern: ${f.pattern}\n`);
            file.write(`Address: ${f.address}\n`);
            file.write(`Text: ${f.text}\n`);
            file.write('-'.repeat(80) + '\n');
        });
        file.close();

        console.log(`\n[+] Found ${findings.length} matches!`);
        console.log(`[+] Results saved to: ${logFile}`);
    } else {
        console.log('\n[-] No matches found');
    }
}

// Scan immediately
console.log('[*] Starting memory scan in 3 seconds...');
console.log('[*] Make sure you sent a message with MEMORYDUMP_12345!');
setTimeout(scanMemory, 3000);

// Scan periodically
setInterval(() => {
    console.log('\n[*] Running periodic scan...');
    scanMemory();
}, 30000);

console.log('[*] Memory scraper active. Ctrl+C to stop.');

// Arrays to store the extracted data
let eapols = [];
let beacons = [];
let packetCount = 0; // Add packetCount as global variable

// DOM elements
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const status = document.getElementById('status');
const results = document.getElementById('results');

// Handle drag and drop events
['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, preventDefaults, false);
});

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, highlight, false);
});

['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, unhighlight, false);
});

function highlight(e) {
    dropZone.classList.add('dragover');
}

function unhighlight(e) {
    dropZone.classList.remove('dragover');
}

dropZone.addEventListener('drop', handleDrop, false);
fileInput.addEventListener('change', handleFileSelect, false);

function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0 && files[0].name.endsWith('.pcap')) {
        handleFiles(files);
    } else {
        status.textContent = 'Please drop a valid PCAP file';
    }
}

function handleFileSelect(e) {
    const files = e.target.files;
    if (files.length > 0) {
        handleFiles(files);
    }
}

function handleFiles(files) {
    const file = files[0];
    if (!file.name.endsWith('.pcap')) {
        status.textContent = 'Please select a valid PCAP file';
        return;
    }
    processFile(file);
}

function processFile(file) {
    status.textContent = 'Reading file...';
    results.innerHTML = ''; // Clear results when new file is uploaded
    eapols = [];
    beacons = [];
    packetCount = 0; // Reset packetCount

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const buffer = e.target.result;
            const data = new Uint8Array(buffer);
            
            // Check file size
            if (data.length < 24) {
                throw new Error('File too small to be a valid PCAP file');
            }

            // Check PCAP magic number and determine endianness
            const magic = readUInt32(data, 0, true);
            console.log('PCAP Magic Number:', magic.toString(16));
            
            let isLittleEndian;
            if (magic === 0xa1b2c3d4) {
                isLittleEndian = true;
                console.log('Detected little-endian PCAP format');
            } else if (magic === 0xd4c3b2a1) {
                isLittleEndian = false;
                console.log('Detected big-endian PCAP format');
            } else if (magic === 0x0a0d0d0a) {
                throw new Error('This appears to be a PCAPNG file. Please save as PCAP format in Wireshark (File -> Save As -> Wireshark/tcpdump/... - pcap)');
            } else {
                throw new Error(`Invalid PCAP magic number: 0x${magic.toString(16)}. Expected 0xa1b2c3d4 or 0xd4c3b2a1`);
            }

            // Read and validate PCAP header
            const versionMajor = data[4] | (data[5] << 8);
            const versionMinor = data[6] | (data[7] << 8);
            console.log(`PCAP Version: ${versionMajor}.${versionMinor}`);
            
            const thiszone = readUInt32(data, 8, isLittleEndian);
            const sigfigs = readUInt32(data, 12, isLittleEndian);
            const snaplen = readUInt32(data, 16, isLittleEndian);
            const network = readUInt32(data, 20, isLittleEndian);
            
            console.log('Network Type:', network);
            console.log('Snap Length:', snaplen);
            
            // Check network type (should be 105 for IEEE 802.11)
            if (network !== 105) {
                throw new Error(`Not a wireless capture file. Network type is ${network}, expected 105 for IEEE 802.11`);
            }

            status.textContent = 'Parsing packets...';
            let offset = 24; // Skip PCAP header

            console.log('Starting packet processing at offset:', offset);
            console.log('Total file size:', data.length);

            while (offset < data.length) {
                try {
                    // Read packet header
                    const timestamp = readUInt32(data, offset, isLittleEndian);
                    const timestampMicros = readUInt32(data, offset + 4, isLittleEndian);
                    const packetLength = readUInt32(data, offset + 8, isLittleEndian);
                    const originalLength = readUInt32(data, offset + 12, isLittleEndian);

                    console.log(`Packet ${packetCount + 1}:`, {
                        offset,
                        timestamp,
                        timestampMicros,
                        packetLength,
                        originalLength
                    });

                    // Validate packet
                    if (packetLength === 0 || packetLength > 10000) {
                        console.warn(`Invalid packet length ${packetLength} at offset ${offset}`);
                        break;
                    }
                    
                    if (offset + 16 + packetLength > data.length) {
                        console.warn(`Packet extends beyond file end at offset ${offset}`);
                        break;
                    }

                    // Process packet
                    const packetData = data.slice(offset + 16, offset + 16 + packetLength);
                    
                    // Log first few bytes of packet for debugging
                    console.log('Packet data (first 32 bytes):', 
                        Array.from(packetData.slice(0, 32))
                            .map(b => b.toString(16).padStart(2, '0'))
                            .join(' ')
                    );
                    
                    processPacket(packetData, timestamp, timestampMicros);
                    
                    offset += 16 + packetLength;
                    packetCount++;
                    
                    if (packetCount % 100 === 0) {
                        status.textContent = `Parsing packets... (${packetCount} packets processed)`;
                    }
                } catch (err) {
                    console.warn('Error processing packet:', err);
                    offset += 16; // Skip to next packet
                }
            }

            console.log(`Finished processing ${packetCount} packets`);
            console.log(`Found ${beacons.length} beacons and ${eapols.length} PMKIDs`);

            // Generate PMKIDs
            status.textContent = 'Generating PMKIDs...';
            generatePMKIDs();

        } catch (err) {
            console.error('Error parsing capture file:', err);
            status.textContent = `Error: ${err.message}`;
        }
    };

    reader.onerror = function() {
        status.textContent = 'Error reading file';
    };

    reader.readAsArrayBuffer(file);
}

function updateStatus(message) {
    status.textContent = message;
    console.log(message);
}

function readUInt32(data, offset, littleEndian) {
    if (littleEndian) {
        return ((data[offset] & 0xff) |
                ((data[offset + 1] & 0xff) << 8) |
                ((data[offset + 2] & 0xff) << 16) |
                ((data[offset + 3] & 0xff) << 24)) >>> 0;
    } else {
        return (((data[offset] & 0xff) << 24) |
                ((data[offset + 1] & 0xff) << 16) |
                ((data[offset + 2] & 0xff) << 8) |
                (data[offset + 3] & 0xff)) >>> 0;
    }
}

function parsePCAP(buffer) {
    try {
        updateStatus('Starting PCAP parsing...');
        const data = new Uint8Array(buffer);
        let offset = 0;
        let packetCount = 0;

        // Check file size
        if (data.length < 24) {
            throw new Error('File too small to be a valid PCAP file');
        }

        // Check magic number to determine endianness
        const magic = readUInt32(data, 0, false);
        const isLittleEndian = (magic === 0xA1B2C3D4);
        
        if (!isLittleEndian && magic !== 0xD4C3B2A1) {
            throw new Error('Invalid PCAP file format');
        }

        // Read and validate PCAP header
        const versionMajor = data[4] | (data[5] << 8);
        const versionMinor = data[6] | (data[7] << 8);
        const thiszone = readUInt32(data, 8, isLittleEndian);
        const sigfigs = readUInt32(data, 12, isLittleEndian);
        const snaplen = readUInt32(data, 16, isLittleEndian);
        const network = readUInt32(data, 20, isLittleEndian);

        // Validate network type (should be 105 for IEEE 802.11)
        if (network !== 105) {
            throw new Error('Not a WiFi capture file (network type should be 105 for IEEE 802.11)');
        }

        // Skip PCAP header (24 bytes)
        offset += 24;
        updateStatus('Reading packets...');

        while (offset < data.length) {
            try {
                // Read packet header
                const timestamp = readUInt32(data, offset, isLittleEndian);
                const microseconds = readUInt32(data, offset + 4, isLittleEndian);
                const capturedLength = readUInt32(data, offset + 8, isLittleEndian);
                const originalLength = readUInt32(data, offset + 12, isLittleEndian);
                offset += 16;

                // Validate packet length
                if (capturedLength === 0 || capturedLength > 10000 || offset + capturedLength > data.length) {
                    console.warn(`Skipping invalid packet at offset ${offset}: length=${capturedLength}`);
                    break;
                }

                // Read packet data
                const packetData = data.slice(offset, offset + capturedLength);
                offset += capturedLength;
                packetCount++;

                // Update status every 1000 packets
                if (packetCount % 1000 === 0) {
                    updateStatus(`Processed ${packetCount} packets...`);
                }

                // Process WiFi packet
                if (packetData.length > 24) {
                    try {
                        const frameControl = (packetData[0] << 8) | packetData[1];
                        const type = (frameControl >> 2) & 0x3;
                        const subtype = (frameControl >> 4) & 0xF;

                        // Beacon frame (type 0, subtype 8)
                        if (type === 0 && subtype === 8) {
                            if (packetData.length >= 38) {  // Minimum length for beacon frame
                                const bssid = Array.from(packetData.slice(16, 22))
                                    .map(b => b.toString(16).padStart(2, '0'))
                                    .join('');
                                
                                // Find SSID in the beacon frame
                                let offset = 36; // Start after fixed beacon frame header
                                while (offset < packetData.length) {
                                    const elementId = packetData[offset];
                                    const elementLength = packetData[offset + 1];
                                    
                                    // SSID element ID is 0
                                    if (elementId === 0 && elementLength > 0) {
                                        const ssidBytes = packetData.slice(offset + 2, offset + 2 + elementLength);
                                        try {
                                            const ssid = new TextDecoder().decode(ssidBytes);
                                            if (ssid && ssid.length > 0) {
                                                const info = [bssid, ssid];
                                                if (!beacons.some(b => b[0] === info[0])) {
                                                    beacons.push(info);
                                                    console.log('Found beacon:', bssid, ssid);
                                                }
                                            }
                                        } catch (err) {
                                            console.warn('Error decoding SSID:', err);
                                        }
                                        break;
                                    }
                                    
                                    // Move to next element
                                    offset += 2 + elementLength;
                                }
                            }
                        }
                        // QoS Data frame (type 2, subtype 8)
                        else if (type === 2 && subtype === 8) {
                            if (packetData.length >= 26) {  // Minimum length for QoS data frame
                                const bssid = Array.from(packetData.slice(4, 10))
                                    .map(b => b.toString(16).padStart(2, '0'))
                                    .join('');
                                const sta = Array.from(packetData.slice(10, 16))
                                    .map(b => b.toString(16).padStart(2, '0'))
                                    .join('');
                                
                                // Look for PMKID in the packet
                                const data = packetData.slice(24);
                                for (let i = 0; i < data.length - 16; i++) {
                                    if (data[i] === 0x01 && data[i + 1] === 0x0C) { // PMKID tag
                                        const pmkid = Array.from(data.slice(i + 2, i + 18))
                                            .map(b => b.toString(16).padStart(2, '0'))
                                            .join('');
                                        
                                        const info = [bssid, sta, pmkid];
                                        if (!eapols.some(e => e[0] === info[0] && e[1] === info[1])) {
                                            eapols.push(info);
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    } catch (packetErr) {
                        console.warn('Error processing WiFi packet:', packetErr);
                        continue;
                    }
                }
            } catch (packetErr) {
                console.warn('Error reading packet header:', packetErr);
                break;
            }
        }

        updateStatus(`Finished processing ${packetCount} packets`);
        generatePMKIDs();
    } catch (err) {
        status.textContent = 'Error parsing capture file: ' + err.message;
        console.error('PCAP parsing error:', err);
    }
}

function processPacket(packetData, timestamp, timestampMicros) {
    try {
        // Check if we have enough data for a WiFi packet
        if (!packetData || packetData.length < 24) {
            return;
        }

        // Get frame control field
        const frameControl = (packetData[0] << 8) | packetData[1];
        const type = (frameControl >> 2) & 0x3;
        const subtype = (frameControl >> 4) & 0xF;

        console.log(`Processing packet: type=${type}, subtype=${subtype}, length=${packetData.length}`);

        // Process Beacon frames (type 0, any subtype)
        if (type === 0) {
            console.log('Found management frame');
            if (packetData.length >= 38) {  // Minimum length for beacon frame
                const bssid = Array.from(packetData.slice(16, 22))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
                
                console.log('Frame BSSID:', bssid);
                
                // Find SSID in the frame
                let offset = 36; // Start after fixed frame header
                while (offset < packetData.length) {
                    const elementId = packetData[offset];
                    const elementLength = packetData[offset + 1];
                    
                    console.log(`Element ID: ${elementId}, Length: ${elementLength}`);
                    
                    // SSID element ID is 0
                    if (elementId === 0) {
                        if (elementLength > 0) {
                            const ssidBytes = packetData.slice(offset + 2, offset + 2 + elementLength);
                            console.log('SSID bytes:', Array.from(ssidBytes).map(b => b.toString(16).padStart(2, '0')).join(' '));
                            
                            try {
                                const ssid = new TextDecoder().decode(ssidBytes);
                                console.log('Decoded SSID:', ssid);
                                
                                if (ssid && ssid.length > 0) {
                                    // Check if we already have this BSSID
                                    const existingIndex = beacons.findIndex(b => b[0] === bssid);
                                    if (existingIndex === -1) {
                                        // New BSSID, add it
                                        beacons.push([bssid, ssid]);
                                        console.log('Added new beacon:', { bssid, ssid });
                                    } else if (beacons[existingIndex][1] === '') {
                                        // Update empty SSID
                                        beacons[existingIndex][1] = ssid;
                                        console.log('Updated empty SSID:', { bssid, ssid });
                                    }
                                }
                            } catch (err) {
                                console.warn('Error decoding SSID:', err);
                            }
                        }
                        break;
                    }
                    
                    // Move to next element
                    offset += 2 + elementLength;
                    if (offset >= packetData.length) break;
                }
            }
        }
        // Process Data frames (type 2)
        else if (type === 2) {
            if (packetData.length >= 26) {  // Minimum length for data frame
                const bssid = Array.from(packetData.slice(4, 10))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
                const sta = Array.from(packetData.slice(10, 16))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
                
                console.log(`Processing data frame: BSSID=${bssid}, STA=${sta}`);
                
                // Look for PMKID in the packet
                const data = packetData.slice(24);
                
                // Search for PMKID in various formats
                for (let i = 0; i < data.length - 16; i++) {
                    // Check for PMKID tag (0x01 0x0C)
                    if (data[i] === 0x01 && data[i + 1] === 0x0C) {
                        console.log(`Found PMKID tag at offset ${i}: ${data[i].toString(16)} ${data[i + 1].toString(16)}`);
                        
                        const pmkid = Array.from(data.slice(i + 2, i + 18))
                            .map(b => b.toString(16).padStart(2, '0'))
                            .join('');
                        
                        // Verify that this BSSID exists in our beacon list
                        const bssidExists = beacons.some(b => b[0] === bssid);
                        if (!bssidExists) {
                            console.log(`Warning: Found PMKID for unknown BSSID ${bssid}, skipping`);
                            continue;
                        }

                        const info = [bssid, sta, pmkid];
                        if (!eapols.some(e => e[0] === info[0] && e[1] === info[1])) {
                            eapols.push(info);
                            console.log('Found PMKID:', bssid, sta, pmkid);
                        }
                        break;
                    }
                    // Check for Flipper Zero format (0xdd 0x09)
                    else if (data[i] === 0xdd && data[i + 1] === 0x09) {
                        console.log(`Found Flipper Zero PMKID tag at offset ${i}`);
                        
                        const pmkid = Array.from(data.slice(i + 2, i + 18))
                            .map(b => b.toString(16).padStart(2, '0'))
                            .join('');
                        
                        // Verify that this BSSID exists in our beacon list
                        const bssidExists = beacons.some(b => b[0] === bssid);
                        if (!bssidExists) {
                            console.log(`Warning: Found PMKID for unknown BSSID ${bssid}, skipping`);
                            continue;
                        }

                        const info = [bssid, sta, pmkid];
                        if (!eapols.some(e => e[0] === info[0] && e[1] === info[1])) {
                            eapols.push(info);
                            console.log('Found PMKID (Flipper):', bssid, sta, pmkid);
                        }
                        break;
                    }
                    // Check for raw PMKID (16 consecutive non-zero bytes)
                    else if (i + 16 <= data.length) {
                        let isPMKID = true;
                        for (let j = 0; j < 16; j++) {
                            if (data[i + j] === 0) {
                                isPMKID = false;
                                break;
                            }
                        }
                        if (isPMKID) {
                            const pmkid = Array.from(data.slice(i, i + 16))
                                .map(b => b.toString(16).padStart(2, '0'))
                                .join('');
                            
                            // Verify that this BSSID exists in our beacon list
                            const bssidExists = beacons.some(b => b[0] === bssid);
                            if (!bssidExists) {
                                console.log(`Warning: Found PMKID for unknown BSSID ${bssid}, skipping`);
                                continue;
                            }

                            const info = [bssid, sta, pmkid];
                            if (!eapols.some(e => e[0] === info[0] && e[1] === info[1])) {
                                eapols.push(info);
                                console.log('Found potential PMKID in raw data:', bssid, sta, pmkid);
                            }
                        }
                    }
                }
            }
        }
    } catch (err) {
        console.warn('Error processing packet:', err);
    }
}

function getSSIDName(bssid) {
    // Try to find SSID in beacons
    const beacon = beacons.find(b => b[0] === bssid);
    if (beacon && beacon[1]) {
        console.log('Found SSID for BSSID:', {
            bssid: bssid,
            ssid: beacon[1]
        });
        return beacon[1];
    }
    console.log('No SSID found for BSSID:', bssid);
    return 'Unknown Network';
}

function findSSIDFromBeacons(bssid) {
    // Search through all beacon frames to find matching SSID
    for (const beacon of beacons) {
        if (beacon[0] === bssid) {
            return beacon[1];
        }
    }
    return '';
}

function generatePMKIDs() {
    console.log('Current beacons:', beacons);
    console.log('Found BSSIDs:', beacons.map(b => b[0]).join(', '));
    const pmkids = [];
    const displayPmkids = []; // Array to store display-friendly PMKIDs
    
    for (const eapol of eapols) {
        // Verify that this BSSID exists in our beacon list
        const bssidExists = beacons.some(b => b[0] === eapol[0]);
        if (!bssidExists) {
            console.log(`Warning: Skipping PMKID for unknown BSSID ${eapol[0]}`);
            continue;
        }

        // Find SSID for this BSSID
        const ssid = findSSIDFromBeacons(eapol[0]);
        const displaySSID = ssid || 'Hidden Network';

        // Convert SSID to hex for hashcat format
        const ssidHex = Array.from(new TextEncoder().encode(ssid || ''))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
        const pmkid = `${eapol[2]}*${eapol[0]}*${eapol[1]}*${ssidHex}`;
        
        if (!pmkids.includes(pmkid)) {
            pmkids.push(pmkid);
            displayPmkids.push({
                hash: eapol[2],
                bssid: eapol[0],
                sta: eapol[1],
                ssid: ssid,
                ssidName: displaySSID
            });
        }
    }

    // Update the display
    if (displayPmkids.length > 0) {
        const pmkidList = document.createElement('div');
        pmkidList.className = 'pmkid-list';
        
        displayPmkids.forEach((pmkid, index) => {
            const pmkidItem = document.createElement('div');
            pmkidItem.className = 'pmkid-item';
            
            const details = document.createElement('div');
            details.className = 'pmkid-details';
            details.innerHTML = `
                PMKID #${index + 1}<br>
                BSSID: ${pmkid.bssid || 'Unknown'}<br>
                STA: ${pmkid.sta || 'Unknown'}<br>
                SSID: ${pmkid.ssidName}
            `;
            
            const downloadBtn = document.createElement('button');
            downloadBtn.className = 'upload-btn';
            downloadBtn.textContent = `Download PMKID #${index + 1}`;
            downloadBtn.onclick = () => {
                const blob = new Blob([pmkids[index]], { type: 'text/plain' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                const filename = pmkid.ssidName !== 'Hidden Network' ? 
                    `${pmkid.ssidName}.pmkid` : `hidden_${pmkid.bssid}.pmkid`;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            };
            
            pmkidItem.appendChild(details);
            pmkidItem.appendChild(downloadBtn);
            pmkidList.appendChild(pmkidItem);
        });

        results.appendChild(pmkidList);

        // Add download all section
        const downloadSection = document.createElement('div');
        downloadSection.className = 'download-section';
        
        const downloadAllBtn = document.createElement('button');
        downloadAllBtn.className = 'upload-btn';
        downloadAllBtn.textContent = 'Download All PMKIDs';
        downloadAllBtn.onclick = () => {
            const blob = new Blob([pmkids.join('\n')], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'all_pmkids.txt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        };
        
        downloadSection.appendChild(downloadAllBtn);
        results.appendChild(downloadSection);

        status.textContent = `Found ${pmkids.length} PMKID(s) in ${packetCount} packets`;
    } else {
        status.textContent = 'No PMKIDs found in the capture file';
    }

    return pmkids;
} 
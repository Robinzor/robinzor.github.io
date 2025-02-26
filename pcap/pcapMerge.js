const fileInput = document.getElementById('fileInput');
const progressBar = document.getElementById('progress-bar');
const progressContainer = document.getElementById('progress-container');
const mergeButton = document.getElementById('mergeButton');
const downloadLink = document.getElementById('downloadLink');
const statusText = document.createElement('div');
statusText.style.marginTop = '10px';
document.body.appendChild(statusText);

const workerScript = `
self.onmessage = async function (event) {
    const files = event.data.files;
    let globalHeader = null;
    let mergedPackets = [];

    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        self.postMessage({ status: \`Processing \${file.name} (\${i + 1}/\${files.length})...\` });

        try {
            const { header, filePackets } = await parsePCAP(file);
            if (!globalHeader) globalHeader = header;
            mergedPackets.push(...filePackets);
        } catch (error) {
            self.postMessage({ error: \`Error processing \${file.name}: \${error.message}\` });
        }

        self.postMessage({ progress: ((i + 1) / files.length) * 100 });
    }

    mergedPackets.sort((a, b) => a.timestamp - b.timestamp);
    const mergedPCAP = createPCAP(globalHeader, mergedPackets);

    self.postMessage({ done: mergedPCAP });
};

function parsePCAP(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();

        reader.onload = function (event) {
            try {
                const data = new Uint8Array(event.target.result);
                const header = data.slice(0, 24); // PCAP header
                const filePackets = extractPackets(data);
                resolve({ header, filePackets });
            } catch (error) {
                reject(error);
            }
        };

        reader.onerror = () => reject(new Error('File reading error'));

        // Lees slechts een beperkt deel van het bestand in
        const CHUNK_SIZE = 10 * 1024 * 1024; // 10 MB per keer
        reader.readAsArrayBuffer(file.slice(0, CHUNK_SIZE));
    });
}

function extractPackets(data) {
    let packets = [];
    let offset = 24; // Skip PCAP global header
    const MAX_PACKETS = 50000; // Beperk het aantal te verwerken packets per keer

    while (offset + 16 <= data.length) {
        const tsSec = data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
        const capturedLength = data[offset + 8] | (data[offset + 9] << 8) | (data[offset + 10] << 16) | (data[offset + 11] << 24);

        if (capturedLength <= 0 || offset + 16 + capturedLength > data.length) {
            break;
        }

        packets.push({ timestamp: tsSec, data: data.slice(offset, offset + 16 + capturedLength) });

        if (packets.length >= MAX_PACKETS) {
            console.warn("Max packets reached, breaking early");
            break;
        }

        offset += 16 + capturedLength;
    }
    return packets;
}

function createPCAP(header, packets) {
    let mergedData = [header];
    packets.forEach(packet => mergedData.push(packet.data));
    return new Blob(mergedData, { type: 'application/octet-stream' });
}
`;

const workerBlob = new Blob([workerScript], { type: 'application/javascript' });
const worker = new Worker(URL.createObjectURL(workerBlob));

worker.onmessage = function (event) {
    if (event.data.progress !== undefined) {
        progressBar.style.width = event.data.progress + '%';
    } else if (event.data.status) {
        statusText.innerHTML = event.data.status;
    } else if (event.data.error) {
        console.error(event.data.error);
        statusText.innerHTML = event.data.error;
    } else if (event.data.done) {
        const blobURL = URL.createObjectURL(event.data.done);
        downloadLink.href = blobURL;
        downloadLink.download = 'merged.pcap';
        downloadLink.style.display = 'block';
        statusText.innerHTML = 'Merge complete. Ready to download.';
        progressBar.style.width = '100%';
    }
};

fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
        let fileNames = Array.from(fileInput.files).map(file => file.name).join(', ');
        statusText.innerHTML = `Selected files: ${fileNames}`;
    }
});

mergeButton.addEventListener('click', () => {
    const files = fileInput.files;
    if (files.length < 2) {
        alert('Select at least two PCAP files.');
        return;
    }

    progressContainer.style.display = 'block';
    statusText.innerHTML = 'Starting merge...';
    worker.postMessage({ files });
});

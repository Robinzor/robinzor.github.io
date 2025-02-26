const fileInput = document.getElementById('fileInput');
const progressBar = document.getElementById('progress-bar');
const progressContainer = document.getElementById('progress-container');
const mergeButton = document.getElementById('mergeButton');
const downloadLink = document.getElementById('downloadLink');
const statusText = document.createElement('div');
statusText.style.marginTop = '10px';
document.body.appendChild(statusText);

const workerBlob = new Blob([`
self.onmessage = async function (event) {
    const files = event.data.files;
    let globalHeader = null;
    let mergedPackets = [];
    let totalChunks = 0;
    let loadedChunks = 0;

    for (let file of files) {
        try {
            const { filePackets } = await parsePCAP(file);
            totalChunks += filePackets.length;
        } catch (error) {
            self.postMessage({ error: \`Error scanning \${file.name}: \${error.message}\` });
        }
    }

    for (let i = 0; i < files.length; i++) {
        try {
            const { header, filePackets } = await parsePCAP(files[i]);
            if (!globalHeader) globalHeader = header;

            for (let j = 0; j < filePackets.length; j++) {
                mergedPackets.push(filePackets[j]);
                loadedChunks++;

                if (loadedChunks % 1000 === 0 || loadedChunks === totalChunks) {
                    self.postMessage({ progress: ((loadedChunks / totalChunks) * 100).toFixed(1), status: \`Chunk \${loadedChunks} / \${totalChunks}\` });
                }
            }
        } catch (error) {
            self.postMessage({ error: \`Error processing \${files[i].name}: \${error.message}\` });
        }
    }

    mergedPackets.sort((a, b) => a.timestamp - b.timestamp);
    const mergedPCAP = createPCAP(globalHeader, mergedPackets);
    self.postMessage({ done: mergedPCAP });
};

async function parsePCAP(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = function (event) {
            try {
                const data = new Uint8Array(event.target.result);
                resolve({ header: data.slice(0, 24), filePackets: extractPackets(data) });
            } catch (error) {
                reject(error);
            }
        };
        reader.onerror = () => reject(new Error('File reading error'));
        reader.readAsArrayBuffer(file);
    });
}

function extractPackets(data) {
    let packets = [];
    let offset = 24;

    while (offset + 16 <= data.length) {
        const tsSec = (data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));
        const capturedLength = (data[offset + 8] | (data[offset + 9] << 8) | (data[offset + 10] << 16) | (data[offset + 11] << 24));

        if (capturedLength <= 0 || offset + 16 + capturedLength > data.length) break;

        packets.push({ timestamp: tsSec, data: data.slice(offset, offset + 16 + capturedLength) });
        offset += 16 + capturedLength;
    }
    return packets;
}

function createPCAP(globalHeader, packets) {
    return new Blob([globalHeader, ...packets.map(p => p.data)], { type: 'application/octet-stream' });
}
`], { type: 'application/javascript' });

const worker = new Worker(URL.createObjectURL(workerBlob));

worker.onmessage = function (event) {
    if (event.data.progress !== undefined) {
        progressBar.style.width = event.data.progress + '%';
        statusText.innerHTML = `Merging... ${event.data.progress}% completed (${event.data.status})`;
    } else if (event.data.status) {
        statusText.innerHTML = event.data.status;
    } else if (event.data.error) {
        console.error(event.data.error);
        statusText.innerHTML = `<span style='color: red;'>${event.data.error}</span>`;
    } else if (event.data.done) {
        const blobURL = URL.createObjectURL(event.data.done);
        downloadLink.href = blobURL;
        downloadLink.download = 'merged.pcap';
        downloadLink.style.display = 'block';
        statusText.innerHTML = '<strong>Merge complete. Ready to download.</strong>';
        progressBar.style.width = '100%';
    }
};

fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
        statusText.innerHTML = `Selected files: ${Array.from(fileInput.files).map(file => file.name).join(', ')}`;
    }
});

mergeButton.addEventListener('click', () => {
    if (fileInput.files.length < 2) {
        alert('Select at least two PCAP files.');
        return;
    }
    progressContainer.style.display = 'block';
    statusText.innerHTML = 'Starting merge...';
    worker.postMessage({ files: fileInput.files });
});

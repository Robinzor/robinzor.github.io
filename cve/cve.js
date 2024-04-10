// Fetches CPEs and sets up expandable sections to load CVEs
async function getCPE() {
    const query = document.getElementById('cpeQuery').value;
    const url = `https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=${encodeURIComponent(query)}`;
    try {
        const response = await fetch(url);
        const data = await response.json();
        const cpeList = document.getElementById('cpeResults');
        cpeList.innerHTML = ''; // Clear previous results

        data.products.forEach((product, index) => {
            const cpe = product.cpe;
            const li = document.createElement('li');
            const title = cpe.titles.find(title => title.lang === "en")?.title || "No title available";
            li.textContent = title;
            li.style.cursor = "pointer";

            // Create a container for CVEs related to this CPE
            const cveContainer = document.createElement('ul');
            cveContainer.id = `cve-container-${index}`;
            cveContainer.style.display = "none"; // Initially hidden

            li.onclick = () => {
                const isVisible = cveContainer.style.display === "block";
                cveContainer.style.display = isVisible ? "none" : "block";
                
                // Fetch and display CVEs only if not fetched previously
                if (!isVisible && cveContainer.childElementCount === 0) {
                    getCVE(cpe.cpeName, cveContainer.id);
                }
            };

            cpeList.appendChild(li);
            cpeList.appendChild(cveContainer); // Append the container for CVEs
        });
    } catch (error) {
        console.error("Error fetching CPE data:", error);
        cpeList.innerText = `Error: ${error.message}`;
    }
}

// Fetches CVEs for the selected CPE and displays them in the specified container
async function getCVE(cpeName, containerId) {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${encodeURIComponent(cpeName)}`;
    try {
        const response = await fetch(url);
        const data = await response.json();
        const cveContainer = document.getElementById(containerId);

        if (data && data.vulnerabilities) {
            data.vulnerabilities.forEach((vulnerability, index) => {
                const cve = vulnerability.cve;
                const cveLi = document.createElement('li');
                const cveDetailsDiv = document.createElement('div'); // Detail container for each CVE

                cveLi.textContent = cve.id;
                cveLi.style.cursor = 'pointer';
                cveLi.setAttribute('data-cve-id', cve.id); // Set the CVE ID as a data attribute

                // Initially hide the details container
                cveDetailsDiv.id = `cve-details-${index}`;
                cveDetailsDiv.style.display = 'none';
                cveDetailsDiv.className = 'cve-details';
                cveDetailsDiv.textContent = 'Click to load details';

                // Click event for each CVE to toggle the details
                cveLi.addEventListener('click', async function() {
                    const currentCveId = this.getAttribute('data-cve-id');
                    const detailsDiv = document.getElementById(`cve-details-${index}`);
                    const isVisible = detailsDiv.style.display === 'block';
                    detailsDiv.style.display = isVisible ? 'none' : 'block';

                    // Fetch and display CVE details only if the details are being shown for the first time
                    if (!isVisible && detailsDiv.textContent === 'Click to load details') {
                        detailsDiv.textContent = 'Loading details...';
                        await fetchCveDetails(currentCveId, detailsDiv);
                    }
                });

                cveContainer.appendChild(cveLi);
                cveContainer.appendChild(cveDetailsDiv);
            });
        } else {
            cveContainer.textContent = 'No CVEs found for this CPE.';
        }
    } catch (error) {
        console.error(`Error fetching CVEs for CPE ${cpeName}:`, error);
        const cveContainer = document.getElementById(containerId);
        cveContainer.textContent = `Error: ${error.message}`;
    }
}

// Function to fetch detailed CVE information
async function fetchCveDetails(cveId, detailsDiv) {
    const detailsUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
    try {
        const response = await fetch(detailsUrl);
        const detailsData = await response.json();

        if (detailsData && detailsData.vulnerabilities) {
            // Assuming the API returns the details in a similar structure
            const vulnerabilityDetails = detailsData.vulnerabilities[0]; // Take the first one for example
            // Now you can populate the detailsDiv with the details from vulnerabilityDetails
            // This is just an example, you will need to adjust according to the actual API response
            detailsDiv.textContent = JSON.stringify(vulnerabilityDetails, null, 2);
        } else {
            detailsDiv.textContent = 'No details found for this CVE.';
        }
    } catch (error) {
        console.error(`Error fetching details for CVE ${cveId}:`, error);
        detailsDiv.textContent = `Error: ${error.message}`;
    }
}

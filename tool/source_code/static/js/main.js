document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('emailForm');
    const resultDiv = document.getElementById('result');
    const resultTitle = document.getElementById('resultTitle');
    const resultMessage = document.getElementById('resultMessage');
    const resultDetails = document.getElementById('resultDetails');
    const urlAnalysis = document.getElementById('urlAnalysis');
    const urlList = document.getElementById('urlList');
    const downloadPdfBtn = document.getElementById('downloadPdfBtn');

    // Advanced findings section
    let advancedDiv = document.getElementById('advancedFindings');
    if (!advancedDiv) {
        advancedDiv = document.createElement('div');
        advancedDiv.id = 'advancedFindings';
        advancedDiv.className = 'mt-4';
        resultDiv.appendChild(advancedDiv);
    }

    let lastAnalysisData = null; // Store last analysis for PDF

    function createUrlCard(urlData) {
        const card = document.createElement('div');
        card.className = 'list-group-item';
        
        const isSuspicious = urlData.suspicious_patterns && urlData.suspicious_patterns.length > 0;
        const statusIcon = isSuspicious ? 
            '<i class="bi bi-exclamation-triangle-fill text-warning"></i>' : 
            '<i class="bi bi-check-circle-fill text-success"></i>';
        
        let html = `
            <div class="d-flex w-100 justify-content-between">
                <h6 class="mb-1">${statusIcon} ${urlData.url}</h6>
                <small>${urlData.is_https ? 'HTTPS' : 'HTTP'}</small>
            </div>
            <p class="mb-1">
                <strong>Domain:</strong> ${urlData.domain}.${urlData.tld}
                ${urlData.subdomain ? `<br><strong>Subdomain:</strong> ${urlData.subdomain}` : ''}
            </p>
        `;
        
        if (urlData.suspicious_patterns && urlData.suspicious_patterns.length > 0) {
            html += `
                <div class="mt-2">
                    <strong class="text-warning">Suspicious Patterns:</strong>
                    <ul class="mb-0">
                        ${urlData.suspicious_patterns.map(pattern => `<li>${pattern}</li>`).join('')}
                    </ul>
                </div>
            `;
        }
        
        card.innerHTML = html;
        return card;
    }

    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const emailContent = document.getElementById('emailContent').value;
        if (!emailContent.trim()) {
            alert('Please enter email content to analyze');
            return;
        }

        // Show loading state
        const submitButton = form.querySelector('button[type="submit"]');
        const originalButtonText = submitButton.innerHTML;
        submitButton.innerHTML = '<span class="loading"></span> Analyzing...';
        submitButton.disabled = true;

        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email_content: emailContent })
            });

            const data = await response.json();
            lastAnalysisData = { email_content: emailContent, result: data };
            console.log('Response data:', data); // Debug log

            if (response.ok) {
                // Display results
                resultDiv.style.display = 'block';
                
                // Set alert class based on result
                const alertClass = data.is_phishing ? 'alert-danger' : 'alert-success';
                resultDiv.querySelector('.alert').className = `alert ${alertClass}`;
                
                // Set content
                resultTitle.textContent = data.is_phishing ? '⚠️ Potential Phishing Email Detected' : '✅ Email Appears Legitimate';
                resultMessage.textContent = data.is_phishing ? 
                    'This email shows characteristics of a phishing attempt. Please be cautious.' :
                    'This email appears to be legitimate based on our analysis.';
                
                // Display details if available
                if (data.details) {
                    resultDetails.innerHTML = '<strong>Analysis Details:</strong><br>' + 
                        Object.entries(data.details)
                            .map(([key, value]) => `${key}: ${value}`)
                            .join('<br>');
                }

                // Display URL analysis if available
                console.log('URL Analysis:', data.url_analysis); // Debug log
                if (data.url_analysis && data.url_analysis.length > 0) {
                    console.log('Showing URL analysis section'); // Debug log
                    urlAnalysis.style.display = 'block';
                    urlList.innerHTML = '';
                    data.url_analysis.forEach(urlData => {
                        urlList.appendChild(createUrlCard(urlData));
                    });
                } else {
                    console.log('No URLs found or URL analysis empty'); // Debug log
                    urlAnalysis.style.display = 'none';
                }

                // Display advanced findings
                if (data.advanced_findings && data.advanced_findings.length > 0) {
                    advancedDiv.style.display = 'block';
                    advancedDiv.innerHTML = `<div class="alert alert-warning"><strong>Advanced Findings:</strong><ul>${data.advanced_findings.map(f => `<li>${f}</li>`).join('')}</ul></div>`;
                } else {
                    advancedDiv.style.display = 'none';
                }

                // Show PDF download button
                downloadPdfBtn.style.display = 'inline-block';
            } else {
                throw new Error(data.error || 'Failed to analyze email');
            }
        } catch (error) {
            console.error('Error:', error); // Debug log
            resultDiv.style.display = 'block';
            resultDiv.querySelector('.alert').className = 'alert alert-warning';
            resultTitle.textContent = 'Error';
            resultMessage.textContent = error.message;
            resultDetails.innerHTML = '';
            urlAnalysis.style.display = 'none';
            advancedDiv.style.display = 'none';
            downloadPdfBtn.style.display = 'none';
        } finally {
            // Reset button state
            submitButton.innerHTML = originalButtonText;
            submitButton.disabled = false;
        }
    });

    // Download PDF handler
    downloadPdfBtn.addEventListener('click', async function() {
        if (!lastAnalysisData) return;
        downloadPdfBtn.disabled = true;
        downloadPdfBtn.innerHTML = '<span class="loading"></span> Generating...';
        try {
            const response = await fetch('/report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(lastAnalysisData)
            });
            if (!response.ok) throw new Error('Failed to generate PDF');
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'phishing_report.pdf';
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
        } catch (err) {
            alert('Error generating PDF: ' + err.message);
        } finally {
            downloadPdfBtn.disabled = false;
            downloadPdfBtn.innerHTML = '<i class="bi bi-file-earmark-pdf"></i> Download PDF Report';
        }
    });
}); 
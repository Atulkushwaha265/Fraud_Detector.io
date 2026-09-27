function switchTab(type) {
    document.querySelectorAll('.tab-btn').forEach((btn, index) => {
        const isActive = (type === 'url' && index === 0) || (type === 'email' && index === 1);
        btn.classList.toggle('active', isActive);
        btn.setAttribute('aria-selected', String(isActive));
    });
    document.querySelectorAll('.form-section').forEach(sec => {
        const isActive = sec.id === `${type}-section`;
        sec.classList.toggle('active', isActive);
        sec.hidden = !isActive;
    });
    document.getElementById('result-box').classList.add('hidden');
}

async function checkURL() {
    await submitCheck('/api/check-url', 'urlInput', 'URL');
}

async function checkEmail() {
    await submitCheck('/api/check-email', 'emailInput', 'email');
}

async function submitCheck(endpoint, inputId, label) {
    const button = document.querySelector(`#${inputId}`).closest('.form-section').querySelector('.action-btn');
    const value = document.getElementById(inputId).value.trim();
    if (!value) {
        showResult('Input required', `Please enter a ${label}.`);
        return;
    }

    try {
        button.disabled = true;
        button.classList.add('loading');
        button.textContent = 'Checking...';
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ [inputId === 'urlInput' ? 'url' : 'email']: value })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'The request could not be completed.');
        if (inputId === 'urlInput') {
            window.location.href = `/result?url=${encodeURIComponent(value)}`;
            return;
        }
        showResult(data.status, data.details, data.score);
    } catch (error) {
        showResult('Service error', error.message);
    } finally {
        button.disabled = false;
        button.classList.remove('loading');
        button.textContent = label === 'URL' ? 'Analyze URL' : 'Analyze email';
    }
}

function showResult(status, details, score = null) {
    const resultBox = document.getElementById('result-box');
    const statusSpan = document.getElementById('resultStatus');
    const detailsP = document.getElementById('resultDetails');
    const scoreWrap = document.getElementById('score-wrap');
    const scoreBar = document.getElementById('score-bar');
    const scoreValue = document.getElementById('score-value');

    resultBox.classList.remove('hidden');
    statusSpan.innerText = status;
    detailsP.innerText = details;
    if (typeof score === 'number') {
        scoreWrap.classList.remove('hidden');
        scoreBar.style.width = `${score}%`;
        scoreValue.innerText = `Trust score ${score}/100`;
    } else {
        scoreWrap.classList.add('hidden');
    }

    resultBox.classList.remove('safe', 'suspicious', 'danger');
    if (status === 'Safe') {
        resultBox.classList.add('safe');
        resultBox.style.background = '#e8f8f5';
        statusSpan.style.color = '#27ae60';
    } else if (status === 'Suspicious') {
        resultBox.classList.add('suspicious');
        resultBox.style.background = '#fef9e7';
        statusSpan.style.color = '#f39c12';
    } else {
        resultBox.classList.add('danger');
        resultBox.style.background = '#f9ebea';
        statusSpan.style.color = '#c0392b';
    }
}
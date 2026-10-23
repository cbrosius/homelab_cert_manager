/**
 * HomeLab Certificate Manager - Modern Client Scripts
 */

// Global modern toast notification system
window.showToast = function(message, type = 'info', duration = 4000) {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `modern-toast toast-${type}`;

    let iconName = 'info';
    if (type === 'success') iconName = 'check_circle';
    else if (type === 'error') iconName = 'error';
    else if (type === 'warning') iconName = 'warning';

    toast.innerHTML = `
        <i class="material-icons" style="font-size: 1.25rem;">${iconName}</i>
        <span style="flex-grow: 1;">${message}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px) scale(0.95)';
        setTimeout(() => toast.remove(), 250);
    }, duration);
};

// Materialize M.Toast compatibility layer
window.M = window.M || {};
window.M.Toast = function(options) {
    const text = (options && options.text) || '';
    const classes = (options && options.classes) || '';
    let type = 'info';
    if (classes.includes('red') || classes.includes('error')) type = 'error';
    else if (classes.includes('green') || classes.includes('success')) type = 'success';
    else if (classes.includes('orange') || classes.includes('warning')) type = 'warning';

    window.showToast(text, type, 4000);
};

// Helper for modal dialogues
window.M.Modal = {
    init: function() {},
    getInstance: function(elem) {
        return {
            open: function() { if (elem.showModal) elem.showModal(); else elem.style.display = 'block'; },
            close: function() { if (elem.close) elem.close(); else elem.style.display = 'none'; }
        };
    }
};

window.M.AutoInit = function() {
    // No-op for legacy Materialize calls
};

// Homelab Cert Re-creation
function recreateHomelabCert() {
    if (confirm('Are you sure you want to recreate the Homelab Certificate Manager certificate? The server will need to be restarted afterwards.')) {
        const csrfTokenEl = document.querySelector('input[name="csrf_token"]') || document.getElementById('session_csrf_token');
        const csrfHeaders = csrfTokenEl ? { 'X-CSRF-Token': csrfTokenEl.value } : {};
        fetch('/recreate-homelab-cert', {
            method: 'POST',
            headers: csrfHeaders,
        })
        .then(response => {
            if (response.ok) {
                window.showToast('Certificate recreated successfully. Please restart the server.', 'success');
                setTimeout(() => {
                    window.location.reload();
                }, 1500);
            } else {
                window.showToast('Failed to recreate certificate', 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            window.showToast('Error recreating certificate', 'error');
        });
    }
}

// Initial theme enforcement
document.addEventListener('DOMContentLoaded', function() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('theme', savedTheme);
});
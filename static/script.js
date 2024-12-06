document.addEventListener('DOMContentLoaded', function() {
    // Initialize all Materialize components
    M.AutoInit();

    const profileButton = document.getElementById('profileButton');
    const dropdownMenu = document.getElementById('dropdown1');
    
    profileButton.addEventListener('click', () => {
        dropdownMenu.classList.toggle('hidden');
    });

    // Schließen des Menüs, wenn der Benutzer außerhalb des Menüs klickt
    window.addEventListener('click', (e) => {
        if (!profileButton.contains(e.target) && !dropdownMenu.contains(e.target)) {
            dropdownMenu.classList.add('hidden');
        }
    });

    // Modal Initialisierung
    const aboutModal = document.querySelectorAll('.modal');
    M.Modal.init(aboutModal);

    // Initialize select element
    const elems = document.querySelectorAll('select');
    M.FormSelect.init(elems);

    // Initialize theme on page load
    const savedTheme = localStorage.getItem('theme') || 'light';
    applyTheme(savedTheme);
    
    // Theme switch handler
    const themeSwitch = document.getElementById('theme-switch');
    if (themeSwitch) {
        themeSwitch.addEventListener('click', function(e) {
            e.preventDefault();
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            applyTheme(newTheme);
        });
    }
});

function recreateHomelabCert() {
    if (confirm('Are you sure you want to recreate the Homelab Certificate Manager certificate? The server will need to be restarted afterwards.')) {
        fetch('/recreate-homelab-cert', {
            method: 'POST',
        })
        .then(response => {
            if (response.ok) {
                M.toast({html: 'Certificate recreated successfully. Please restart the server.'});
                // Reload the page after a short delay to allow the toast to be visible
                setTimeout(() => {
                    window.location.reload();
                }, 1500);
            } else {
                M.toast({html: 'Failed to recreate certificate'});
            }
        })
        .catch(error => {
            console.error('Error:', error);
            M.toast({html: 'Error recreating certificate'});
        });
    }
}

function applyTheme(theme) {
    // Validate theme value
    const validThemes = ['light', 'dark'];
    if (!validThemes.includes(theme)) {
        theme = 'light'; // Default to light if invalid
    }
    
    // Apply theme to document
    document.documentElement.setAttribute('data-theme', theme);
    document.body.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    
    // Update theme switch icon if it exists
    const themeSwitch = document.getElementById('theme-switch');
    if (themeSwitch) {
        const icon = themeSwitch.querySelector('i');
        if (icon) {
            icon.textContent = theme === 'dark' ? 'light_mode' : 'dark_mode';
        }
    }
    
    // Force reload styles
    document.body.style.display = 'none';
    document.body.offsetHeight; // Trigger reflow
    document.body.style.display = '';
    
    // Update Materialize components
    M.updateTextFields();
}

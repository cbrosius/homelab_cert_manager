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
            const currentTheme = document.documentElement.getAttribute('theme');
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
                new M.Toast({text: 'Certificate recreated successfully. Please restart the server.'});
                // Reload the page after a short delay to allow the toast to be visible
                setTimeout(() => {
                    window.location.reload();
                }, 1500);
            } else {
                new M.Toast({text: 'Failed to recreate certificate'});
            }
        })
        .catch(error => {
            console.error('Error:', error);
            new M.Toast({text: 'Error recreating certificate'});
        });
    }
}

function applyTheme(theme){
    // Change Theme Setting with a Switch
    const currentTheme = localStorage.getItem('theme');
    const switchElem = document.querySelector('#theme-switch');

    const setTheme = (isDark) => {
        if (isDark) {
            switchElem.classList.add('is-dark');
            switchElem.querySelector('i').innerText = 'light_mode';
            switchElem.title = 'Switch to light mode';
        }
        else {
            switchElem.classList.remove('is-dark');
            switchElem.querySelector('i').innerText = 'dark_mode';
            switchElem.title = 'Switch to dark mode';
        }
    }

    if (switchElem) {
        // Load
        if (currentTheme) setTheme(true);
        // Change
        switchElem.addEventListener('click', e => {
            e.preventDefault();
            if (!switchElem.classList.contains('is-dark')) {
            // Dark Theme
            document.documentElement.setAttribute('theme', 'dark');
            localStorage.setItem('theme', 'dark');
            setTheme(true);
            }
            else {
            // Light Theme
            document.documentElement.removeAttribute('theme');
            localStorage.removeItem('theme');
            setTheme(false);
            }
        });
    }
}
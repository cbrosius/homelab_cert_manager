document.addEventListener('DOMContentLoaded', function() {
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

    // Theme switching functionality
    const currentTheme = localStorage.getItem('theme');
    const switchElem = document.querySelector('#theme-switch');

    const setTheme = (isDark) => {
        if (isDark) {
            switchElem.classList.add('is-dark');
            switchElem.querySelector('i').innerText = 'light_mode';
            switchElem.title = 'Switch to light mode';
            document.documentElement.setAttribute('theme', 'dark');
        } else {
            switchElem.classList.remove('is-dark');
            switchElem.querySelector('i').innerText = 'dark_mode';
            switchElem.title = 'Switch to dark mode';
            document.documentElement.removeAttribute('theme');
        }
    }

    // Load saved theme
    if (currentTheme === 'dark') {
        setTheme(true);
    }

    // Theme switch click handler
    if (switchElem) {
        switchElem.addEventListener('click', e => {
            e.preventDefault();
            if (!switchElem.classList.contains('is-dark')) {
                // Switch to Dark Theme
                localStorage.setItem('theme', 'dark');
                setTheme(true);
            } else {
                // Switch to Light Theme
                localStorage.removeItem('theme');
                setTheme(false);
            }
        });
    }
});

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
});

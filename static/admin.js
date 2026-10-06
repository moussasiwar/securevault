document.addEventListener('DOMContentLoaded', function () {
    // Ouvrir/fermer le menu de rôle
    document.querySelectorAll('.role-dropdown__trigger').forEach(function (trigger) {
        trigger.addEventListener('click', function () {
            const dropdown = trigger.closest('.role-dropdown');
            const wasOpen = dropdown.classList.contains('is-open');
            document.querySelectorAll('.role-dropdown.is-open').forEach(function (d) {
                d.classList.remove('is-open');
            });
            if (!wasOpen) dropdown.classList.add('is-open');
        });
    });

    // Sélectionner un rôle dans le menu
    document.querySelectorAll('.role-dropdown__option').forEach(function (option) {
        option.addEventListener('click', function () {
            const role = option.dataset.role;
            const userId = option.closest('.role-dropdown').dataset.userId;
            document.getElementById('role-input-' + userId).value = role;
            document.getElementById('role-form-' + userId).submit();
        });
    });

    // Fermer le menu si on clique ailleurs
    document.addEventListener('click', function (e) {
        if (!e.target.closest('.role-dropdown')) {
            document.querySelectorAll('.role-dropdown.is-open').forEach(function (d) {
                d.classList.remove('is-open');
            });
        }
    });
});
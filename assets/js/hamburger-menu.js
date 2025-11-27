// Hamburger Menu Toggle Functionality
document.addEventListener('DOMContentLoaded', function() {
    const hamburgerMenu = document.getElementById('hamburgerMenu');
    const sidebar = document.querySelector('.sidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    const mainContent = document.querySelector('.main-content');

    if (hamburgerMenu && sidebar) {
        // Toggle sidebar when hamburger menu is clicked
        hamburgerMenu.addEventListener('click', function() {
            sidebar.classList.toggle('active');
            if (sidebarOverlay) {
                sidebarOverlay.classList.toggle('active');
            }
            if (mainContent) {
                mainContent.classList.toggle('sidebar-active');
            }
            // Toggle hamburger icon animation
            hamburgerMenu.classList.toggle('active');
        });

        // Close sidebar when overlay is clicked
        if (sidebarOverlay) {
            sidebarOverlay.addEventListener('click', function() {
                sidebar.classList.remove('active');
                sidebarOverlay.classList.remove('active');
                if (mainContent) {
                    mainContent.classList.remove('sidebar-active');
                }
                hamburgerMenu.classList.remove('active');
            });
        }

        // Close sidebar when clicking on menu links (mobile)
        const sidebarLinks = sidebar.querySelectorAll('.sidebar-menu a');
        sidebarLinks.forEach(link => {
            link.addEventListener('click', function() {
                // Only close on mobile devices
                if (window.innerWidth <= 768) {
                    sidebar.classList.remove('active');
                    if (sidebarOverlay) {
                        sidebarOverlay.classList.remove('active');
                    }
                    if (mainContent) {
                        mainContent.classList.remove('sidebar-active');
                    }
                    hamburgerMenu.classList.remove('active');
                }
            });
        });

        // Handle window resize
        window.addEventListener('resize', function() {
            if (window.innerWidth > 768) {
                // On desktop, ensure sidebar is visible
                sidebar.classList.remove('active');
                if (sidebarOverlay) {
                    sidebarOverlay.classList.remove('active');
                }
                if (mainContent) {
                    mainContent.classList.remove('sidebar-active');
                }
                hamburgerMenu.classList.remove('active');
            }
        });
    }
});


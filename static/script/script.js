// Create cursor glow element if it doesn't exist
document.addEventListener('DOMContentLoaded', function() {
    if (!document.querySelector('.cursor-glow')) {
        const cursorGlow = document.createElement('div');
        cursorGlow.classList.add('cursor-glow');
        document.body.appendChild(cursorGlow);
    }
    
    // Initialize animations when DOM is loaded
    initializeAnimations();
    
    // Force active class on reveal-text elements immediately
    document.querySelectorAll('.reveal-text').forEach(function(el) {
        el.classList.add('active');
    });
});

// Debug function to check visibility issues
function debugVisibility() {
  console.log('Debug: Checking visibility of key elements');
  
  const keyElements = [
    'body', 
    '#page', 
    '#vision', 
    '#header', 
    '.navbar', 
    '.main-title', 
    '.subtitle-container'
  ];
  
  keyElements.forEach(selector => {
    const element = document.querySelector(selector);
    if (element) {
      const styles = window.getComputedStyle(element);
      console.log(`${selector}: display=${styles.display}, visibility=${styles.visibility}, opacity=${styles.opacity}`);
    } else {
      console.log(`${selector}: Element not found`);
    }
  });
}

// Run debug on page load
document.addEventListener('DOMContentLoaded', function() {
  debugVisibility();
  
  // Force immediate visibility
  document.body.style.opacity = '1';
  document.body.style.visibility = 'visible';
  
  const pageElement = document.getElementById('page');
  if (pageElement) {
    pageElement.style.opacity = '1';
    pageElement.style.visibility = 'visible';
  }

  // Add loaded class to body for page transition
  setTimeout(function() {
    document.body.classList.add('loaded');
  }, 100);
});

// Navbar functionality
document.addEventListener('DOMContentLoaded', function() {
    // Navbar functionality
    const menuToggle = document.querySelector('.navbar-toggle');
    const mobileMenu = document.querySelector('.navbar-menu');
    const navItems = document.querySelectorAll('.nav-item');
    const body = document.querySelector('body');
    const header = document.getElementById('header');
    
    // Mobile menu toggle
    if (menuToggle && mobileMenu) {
        menuToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            mobileMenu.classList.toggle('active');
            menuToggle.classList.toggle('active');
            body.classList.toggle('stop');
            
            // Create overlay when menu is open
            if (mobileMenu.classList.contains('active')) {
                if (!document.querySelector('.mobile-menu-overlay')) {
                    const overlay = document.createElement('div');
                    overlay.classList.add('mobile-menu-overlay');
                    document.body.appendChild(overlay);
                    
                    overlay.addEventListener('click', function() {
                        closeMenu();
                    });
                    
                    setTimeout(() => {
                        overlay.style.opacity = '1';
                    }, 10);
                }
            } else {
                const overlay = document.querySelector('.mobile-menu-overlay');
                if (overlay) {
                    overlay.style.opacity = '0';
                    setTimeout(() => {
                        overlay.remove();
                    }, 300);
                }
            }
        });
        
        // Function to close menu
        function closeMenu() {
            mobileMenu.classList.remove('active');
            menuToggle.classList.remove('active');
            body.classList.remove('stop');
            
            const overlay = document.querySelector('.mobile-menu-overlay');
            if (overlay) {
                overlay.style.opacity = '0';
                setTimeout(() => {
                    overlay.remove();
                }, 300);
            }
        }
        
        // Close menu when clicking a nav item
        navItems.forEach(item => {
            item.addEventListener('click', function(e) {
                // Set the active class
                navItems.forEach(nav => nav.classList.remove('active'));
                this.classList.add('active');
                
                if (window.innerWidth <= 768) {
                    closeMenu();
                }
            });
        });
        
        // Close menu when pressing escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeMenu();
            }
        });
    }

    // Basic sticky header
    window.addEventListener('scroll', function() {
        if (window.scrollY > 10) {
            header.classList.add('sticky');
        } else {
            header.classList.remove('sticky');
        }
    });

    // Handle section tracking for nav items
    handleSectionTracking();
});

// Handle section tracking
function handleSectionTracking() {
    const sections = document.querySelectorAll('section[id]');
    const navItems = document.querySelectorAll('.nav-item');
    
    if (sections.length > 0 && navItems.length > 0) {
        window.addEventListener('scroll', function() {
            let current = '';
            const scrollY = window.scrollY;
            
            sections.forEach(section => {
                const sectionTop = section.offsetTop - 100;
                const sectionHeight = section.offsetHeight;
                
                if (scrollY >= sectionTop && scrollY < sectionTop + sectionHeight) {
                    current = section.getAttribute('id');
                }
            });
            
            navItems.forEach(item => {
                item.classList.remove('active');
                if (item.getAttribute('href') === `#${current}`) {
                    item.classList.add('active');
                }
            });
            
            // If at the top or no section is matched, activate the first nav item
            if (current === '' && navItems.length > 0) {
                navItems[0].classList.add('active');
            }
        });
    }
}

// Add section background initialization
function initializeSectionBackgrounds() {
    // Initialize section orbs
    const sectionOrbs = document.querySelectorAll('.section-orb');
    if (sectionOrbs.length > 0) {
        sectionOrbs.forEach(orb => {
            orb.style.opacity = '0.15';
            orb.style.visibility = 'visible';
        });
    }
    
    // Initialize section grids
    const sectionGrids = document.querySelectorAll('.section-grid');
    if (sectionGrids.length > 0) {
        sectionGrids.forEach(grid => {
            grid.style.opacity = '0.3';
            grid.style.visibility = 'visible';
        });
    }
}

// Initialize animations function
function initializeAnimations() {
    // Add animation classes
    const animatedElements = document.querySelectorAll('.reveal-text, .fade-in, .slide-in');
    
    animatedElements.forEach(element => {
        element.classList.add('active');
    });
    
    // Initialize glitch effect on headings
    document.querySelectorAll('.glitch').forEach(heading => {
        if (heading.getAttribute('data-text') === null && heading.textContent) {
            heading.setAttribute('data-text', heading.textContent);
        }
    });
    
    // Ensure grid background is visible
    const gridBackgrounds = document.querySelectorAll('.grid-background, .section-grid');
    if (gridBackgrounds.length > 0) {
        gridBackgrounds.forEach(grid => {
            grid.style.opacity = '0.4';
            grid.style.visibility = 'visible';
        });
    }
    
    // Ensure orbs are visible
    const orbs = document.querySelectorAll('.orb, .section-orb');
    orbs.forEach(orb => {
        orb.style.opacity = '0.2';
        orb.style.visibility = 'visible';
    });
    
    // Initialize section backgrounds
    initializeSectionBackgrounds();
}

// Smooth scroll for anchor links
document.addEventListener('DOMContentLoaded', function() {
    const links = document.querySelectorAll('a[href^="#"]');

    links.forEach(function(link) {
        link.addEventListener('click', function(event) {
            // Prevent the default action
            event.preventDefault();

            // Get the target element
            var targetId = this.getAttribute('href');
            var targetElement = document.querySelector(targetId);

            // Smooth scroll to target
            if (targetElement) {
                targetElement.scrollIntoTime = Date.now(); // For tracking recent clicks
                window.scrollTo({
                    top: targetElement.offsetTop - 80, // Offset for header
                    behavior: 'smooth'
                });
            }
        });
    });
});

// Ensure visibility of all content
document.addEventListener('DOMContentLoaded', function() {
  // Force visibility of all elements
  document.body.style.opacity = '1';
  document.body.style.visibility = 'visible';
  
  // Remove any potential hiding classes
  const allElements = document.querySelectorAll('*');
  allElements.forEach(element => {
    if (element.style.display === 'none') {
      element.style.display = '';
    }
    if (element.style.visibility === 'hidden') {
      element.style.visibility = 'visible';
    }
    if (element.style.opacity === '0') {
      element.style.opacity = '1';
    }
  });
  
  // Ensure the page container is visible
  const pageContainer = document.getElementById('page');
  if (pageContainer) {
    pageContainer.style.opacity = '1';
    pageContainer.style.visibility = 'visible';
    pageContainer.classList.remove('menuopen');
  }
  
  console.log('Visibility enforcement complete');
});

// Cursor glow effect
document.addEventListener('DOMContentLoaded', function() {
    // Add cursor glow movement
    const cursorGlow = document.querySelector('.cursor-glow');
    
    if (cursorGlow) {
        // Variables for throttling
        let lastX = 0;
        let lastY = 0;
        let ticking = false;
        
        // Set initial CSS variables
        document.documentElement.style.setProperty('--cursor-x', '0px');
        document.documentElement.style.setProperty('--cursor-y', '0px');
        
        document.addEventListener('mousemove', function(e) {
            lastX = e.clientX;
            lastY = e.clientY;
            
            // Throttle the updates using requestAnimationFrame
            if (!ticking) {
                window.requestAnimationFrame(function() {
                    // Update CSS variables instead of direct style manipulation
                    document.documentElement.style.setProperty('--cursor-x', lastX + 'px');
                    document.documentElement.style.setProperty('--cursor-y', lastY + 'px');
                    ticking = false;
                });
                ticking = true;
            }
        });
        
        // Use event delegation for hover effects instead of attaching to each element
        document.body.addEventListener('mouseover', function(e) {
            // Check if the element or its parent is interactive
            const isInteractive = e.target.closest('button, .feature, .card, .btn, a, .social-links a, .navbar-logo, .join-btn, .nav-item');
            
            if (isInteractive) {
                document.documentElement.classList.add('hovering-interactive');
            }
        });
        
        document.body.addEventListener('mouseout', function(e) {
            // Only remove the class if we're not hovering another interactive element
            const stillInteractive = e.relatedTarget && e.relatedTarget.closest('button, .feature, .card, .btn, a, .social-links a, .navbar-logo, .join-btn, .nav-item');
            
            if (!stillInteractive) {
                document.documentElement.classList.remove('hovering-interactive');
            }
        });
    }
});

// Add testimonial cards animation with optimized performance
document.addEventListener('DOMContentLoaded', function() {
    // Only set up if we have testimonial cards
    const testimonialCards = document.querySelectorAll('#testimonials .card');
    if (testimonialCards.length === 0) return;
    
    // Pre-add the hidden class before any animations start
    testimonialCards.forEach(card => {
        card.classList.add('card-hidden');
    });
    
    // Lazy load the images to improve performance
    const lazyImages = document.querySelectorAll('#testimonials .image-box img');
    lazyImages.forEach(img => {
        img.setAttribute('loading', 'lazy');
    });
    
    // Optimize the section orbs for better performance
    const testimonialOrbs = document.querySelectorAll('#testimonials .section-orb');
    testimonialOrbs.forEach(orb => {
        orb.style.animation = 'none';
        orb.style.opacity = '0.08';
        orb.style.width = orb.style.height = '80%';
        orb.style.filter = 'blur(40px)';
    });
    
    // Optimize the section grid
    const testimonialGrid = document.querySelector('#testimonials .section-grid');
    if (testimonialGrid) {
        testimonialGrid.style.opacity = '0.15';
        testimonialGrid.style.backgroundSize = '80px 80px';
    }
    
    // Optimize will-change property usage
    // Add will-change only when scrolling near the testimonials section
    const optimizeWillChange = () => {
        const testimonialSection = document.getElementById('testimonials');
        if (!testimonialSection) return;
        
        const sectionRect = testimonialSection.getBoundingClientRect();
        const windowHeight = window.innerHeight;
        
        // If we're approaching the testimonials section
        if (sectionRect.top < windowHeight * 1.5 && sectionRect.bottom > -windowHeight * 0.5) {
            testimonialCards.forEach(card => {
                card.style.willChange = 'transform, opacity';
            });
        } else {
            testimonialCards.forEach(card => {
                card.style.willChange = 'auto';
            });
        }
    };
    
    // Throttled check function for better performance
    let isChecking = false;
    
    const checkVisibility = () => {
        if (isChecking) return;
        isChecking = true;
        
        const testimonialSection = document.getElementById('testimonials');
        if (!testimonialSection) {
            isChecking = false;
            return;
        }
        
        optimizeWillChange();
        
        const sectionTop = testimonialSection.getBoundingClientRect().top;
        const windowHeight = window.innerHeight;
        
        // If the section is in view
        if (sectionTop < windowHeight * 0.8) {
            testimonialCards.forEach((card, index) => {
                // Use a simpler visibility detection
                setTimeout(() => {
                    card.classList.add('card-visible');
                    card.classList.remove('card-hidden');
                }, index * 150); // Reduced delay between cards
            });
            
            // Remove the scroll listener once animation is complete
            window.removeEventListener('scroll', checkVisibility);
            
            // Remove will-change after animations complete
            setTimeout(() => {
                testimonialCards.forEach(card => {
                    card.style.willChange = 'auto';
                });
            }, testimonialCards.length * 150 + 600);
        }
        
        // Reset throttle
        setTimeout(() => {
            isChecking = false;
        }, 100);
    };
    
    // Check on initial load and add scroll listener
    checkVisibility();
    window.addEventListener('scroll', checkVisibility, { passive: true });
});

// Detect low-performance devices and disable heavy effects
document.addEventListener('DOMContentLoaded', function() {
    // Check if device is mobile or has lower performance
    const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    const isLowPowerMode = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    
    // If mobile or low power mode, add lightweight class to body
    if (isMobile || isLowPowerMode) {
        document.body.classList.add('lightweight-mode');
        
        // Disable cursor glow completely on mobile
        if (isMobile) {
            const cursorGlow = document.querySelector('.cursor-glow');
            if (cursorGlow) {
                cursorGlow.style.display = 'none';
            }
        }
        
        // Reduce or disable some animations
        document.querySelectorAll('.orb, .section-orb').forEach(orb => {
            orb.style.animationDuration = '60s'; // Slow down animations
            orb.style.opacity = '0.1'; // Reduce opacity
        });
        
        // Disable complex animations
        const style = document.createElement('style');
        style.textContent = `
            @media (max-width: 768px) {
                .accent-line { animation: none !important; }
                body::before { opacity: 0.2 !important; animation: none !important; }
                .section-grid { opacity: 0.2 !important; }
                @keyframes floatOrb { 0%, 50%, 100% { transform: none; opacity: 0.1; } }
                @keyframes floatSectionOrb { 0%, 50%, 100% { transform: none; opacity: 0.1; } }
                @keyframes pulseBackground { 0%, 50%, 100% { opacity: 0.4; background-position: 0 0; } }
            }
        `;
        document.head.appendChild(style);
    }
});


document.addEventListener('DOMContentLoaded', function() {
  // Elements
  const container = document.getElementById('container');
  const registerBtn = document.getElementById('register-btn');
  const loginBtn = document.getElementById('login-btn');
  const createAccountLink = document.getElementById('create-account');
  const inputFields = document.querySelectorAll('input:not([type="checkbox"])');
  const socialButtons = document.querySelectorAll('.social-btn');
  
  // Toggle between sign-in and sign-up forms
  if (registerBtn) {
    registerBtn.addEventListener('click', () => {
      container.classList.add('signup-active');
      playPanelSwitchSound();
    });
  }
  
  if (loginBtn) {
    loginBtn.addEventListener('click', (e) => {
      e.preventDefault();
      container.classList.remove('signup-active');
      playPanelSwitchSound();
    });
  }
  
  // For mobile view
  if (createAccountLink) {
    createAccountLink.addEventListener('click', (e) => {
      e.preventDefault();
      container.classList.add('signup-active');
      playPanelSwitchSound();
    });
  }
  
  // Add subtle sound effects (optional - only plays in browsers that support Web Audio API)
  function playPanelSwitchSound() {
    try {
      const audioContext = new (window.AudioContext || window.webkitAudioContext)();
      const oscillator = audioContext.createOscillator();
      const gainNode = audioContext.createGain();
      
      oscillator.type = 'sine';
      oscillator.frequency.setValueAtTime(440, audioContext.currentTime); // A4 note
      oscillator.frequency.exponentialRampToValueAtTime(880, audioContext.currentTime + 0.1); // Pitch up to A5
      
      gainNode.gain.value = 0.1; // Low volume
      
      oscillator.connect(gainNode);
      gainNode.connect(audioContext.destination);
      
      oscillator.start();
      oscillator.stop(audioContext.currentTime + 0.1);
    } catch (e) {
      // Browser doesn't support Web Audio API or another error occurred
      console.log('Sound effect not supported in this browser');
    }
  }
  
  // Add subtle animations to form elements
  inputFields.forEach(input => {
    // Add animation on focus
    input.addEventListener('focus', () => {
      input.parentElement.classList.add('focused');
      addInputRipple(input);
    });
    
    // Remove animation on blur
    input.addEventListener('blur', () => {
      input.parentElement.classList.remove('focused');
      
      // Show validation icon if input has value
      if (input.value.trim() !== '') {
        input.parentElement.classList.add('valid');
      } else {
        input.parentElement.classList.remove('valid');
      }
    });
    
    // Add key press animation
    input.addEventListener('keydown', () => {
      if (!input.parentElement.classList.contains('key-animation')) {
        input.parentElement.classList.add('key-animation');
        setTimeout(() => {
          input.parentElement.classList.remove('key-animation');
        }, 100);
      }
    });
  });
  
  // Add ripple effect to inputs
  function addInputRipple(element) {
    const ripple = document.createElement('span');
    ripple.classList.add('input-ripple');
    element.parentElement.appendChild(ripple);
    
    setTimeout(() => {
      ripple.remove();
    }, 800);
  }
  
  // Add ripple effect to buttons
  document.querySelectorAll('.btn, .social-btn').forEach(button => {
    button.addEventListener('click', function(e) {
      const rect = this.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      
      const ripple = document.createElement('span');
      ripple.classList.add('btn-ripple');
      ripple.style.left = `${x}px`;
      ripple.style.top = `${y}px`;
      
      this.appendChild(ripple);
      
      setTimeout(() => {
        ripple.remove();
      }, 600);
    });
  });
  
  // Add hover effect to social buttons
  socialButtons.forEach(button => {
    button.addEventListener('mouseenter', () => {
      button.classList.add('social-hover');
    });
    
    button.addEventListener('mouseleave', () => {
      button.classList.remove('social-hover');
    });
  });
  
  // Form validation
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    form.addEventListener('submit', function(event) {
      let isValid = true;
      
      // Check each required input
      const requiredInputs = form.querySelectorAll('input[required]');
      requiredInputs.forEach(input => {
        if (input.value.trim() === '') {
          isValid = false;
          input.parentElement.classList.add('error');
          
          // Shake animation for error
          input.parentElement.classList.add('shake');
          
          // Remove error class after 3 seconds
          setTimeout(() => {
            input.parentElement.classList.remove('error');
          }, 3000);
          
          // Remove shake animation after it completes
          setTimeout(() => {
            input.parentElement.classList.remove('shake');
          }, 500);
        }
      });
      
      if (!isValid) {
        event.preventDefault();
      }
    });
  });
  
  // Create dynamic accent lines
  function createDynamicAccentLines() {
    const linesContainer = document.querySelector('.accent-lines');
    const totalLines = Math.floor(window.innerHeight / 200); // Approximately one line per 200px of height
    
    // Remove existing lines
    while (linesContainer.firstChild) {
      linesContainer.removeChild(linesContainer.firstChild);
    }
    
    // Create new lines
    for (let i = 0; i < totalLines; i++) {
      const line = document.createElement('div');
      line.classList.add('accent-line');
      line.style.top = `${(i + 1) * (100 / (totalLines + 1))}%`;
      line.style.animationDuration = `${18 + Math.random() * 12}s`;
      line.style.animationDelay = `${Math.random() * 10}s`;
      linesContainer.appendChild(line);
    }
  }
  
  // Add floating effect to background orbs
  function moveOrbs() {
    const orbs = document.querySelectorAll('.orb');
    orbs.forEach(orb => {
      const speed = Math.random() * 2 + 1;
      const rotation = Math.random() * 360;
      const scale = 0.9 + Math.random() * 0.2;
      
      // Apply random transformations while keeping the original animation
      orb.style.transform = `rotate(${rotation}deg) scale(${scale})`;
    });
  }
  
  // Initialize
  createDynamicAccentLines();
  moveOrbs();
  
  // Handle window resize for accent lines
  window.addEventListener('resize', createDynamicAccentLines);
});

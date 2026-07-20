/** Landing page — public real-time simulation entry */

const SIMULATE_URL = '/analyze.html?mode=simulate';
const SIMULATE_GUEST_URL = '/analyze.html?mode=simulate&guest=1';

function openSimAuthModal() {
  const modal = document.getElementById('sim-auth-modal');
  if (!modal) return;
  modal.classList.remove('hidden');
  document.getElementById('sim-auth-guest')?.focus();
}

function closeSimAuthModal() {
  document.getElementById('sim-auth-modal')?.classList.add('hidden');
}

function goToSimulation({ guest = false } = {}) {
  if (guest) {
    sessionStorage.setItem('cybervault_guest', '1');
    window.location.href = SIMULATE_GUEST_URL;
    return;
  }
  sessionStorage.removeItem('cybervault_guest');
  window.location.href = SIMULATE_URL;
}

function handleSimulerClick() {
  if (Auth.getToken()) {
    goToSimulation({ guest: false });
    return;
  }
  openSimAuthModal();
}

document.addEventListener('DOMContentLoaded', () => {
  const modal = document.getElementById('sim-auth-modal');

  [
    'btn-simuler-temps-reel',
    'btn-simuler-temps-reel-banner',
    'btn-simuler-temps-reel-mid',
    'btn-simuler-temps-reel-cta',
  ].forEach((id) => {
    document.getElementById(id)?.addEventListener('click', handleSimulerClick);
  });

  document.getElementById('sim-auth-guest')?.addEventListener('click', () => {
    goToSimulation({ guest: true });
  });

  modal?.querySelectorAll('[data-close-sim-auth]').forEach((el) => {
    el.addEventListener('click', closeSimAuthModal);
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && modal && !modal.classList.contains('hidden')) {
      closeSimAuthModal();
    }
  });
});

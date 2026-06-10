// ── TOGGLE ECOSYSTEM ──
function toggleEco(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('open');
}

// ── TOGGLE COUSIN CARD ──
function toggleCousin(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('open');
}

// ── TOGGLE NOVEL CARD ──
function toggleNovel(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('open');
}

// ── OPEN ALL ──
function openAll() {
  document.querySelectorAll('.ecosystem, .cousin-card, .novel-card').forEach(el => el.classList.add('open'));
}

// ── CLOSE ALL ──
function closeAll() {
  document.querySelectorAll('.ecosystem, .cousin-card, .novel-card').forEach(el => el.classList.remove('open'));
}

// ── LINK PROMPT ── (for INSERT LINK placeholders)
function insertLink(el, defaultText) {
  const url = prompt('Enter URL for this link:', 'https://');
  if (url && url !== 'https://' && url.trim() !== '') {
    el.href = url;
    el.style.borderColor = 'var(--blue-primary)';
    el.style.borderStyle = 'solid';
    el.style.color = 'var(--blue-primary)';
    el.setAttribute('target', '_blank');
    // Save to localStorage keyed by element id or text
    const key = el.id || el.textContent.trim().substring(0, 40);
    try { localStorage.setItem('mtdf_link_' + key, url); } catch(e) {}
  }
  return false;
}

// ── RESTORE SAVED LINKS ──
function restoreSavedLinks() {
  document.querySelectorAll('.link-rule[data-key], .link-ext[data-key], .link-rd[data-key]').forEach(el => {
    const key = el.getAttribute('data-key');
    try {
      const saved = localStorage.getItem('mtdf_link_' + key);
      if (saved) {
        el.href = saved;
        el.setAttribute('target', '_blank');
        el.style.borderStyle = 'solid';
        el.style.color = 'var(--blue-primary)';
      }
    } catch(e) {}
  });
}

// ── INIT ──
document.addEventListener('DOMContentLoaded', () => {
  // Open first ecosystem in each page by default
  const firstEco = document.querySelector('.ecosystem');
  if (firstEco) firstEco.classList.add('open');

  // Open all novel cards by default
  document.querySelectorAll('.novel-card').forEach(n => n.classList.add('open'));

  // Restore saved links
  restoreSavedLinks();

  // Mark active nav link
  const path = window.location.pathname.split('/').pop();
  document.querySelectorAll('.nav-link').forEach(link => {
    const href = link.getAttribute('href');
    if (href && href === path) {
      link.classList.add('active');
    }
  });

  // Scroll to top button visibility
  const scrollBtn = document.querySelector('.scroll-top');
  if (scrollBtn) {
    window.addEventListener('scroll', () => {
      scrollBtn.style.opacity = window.scrollY > 300 ? '1' : '0';
    });
    scrollBtn.style.opacity = '0';
    scrollBtn.style.transition = 'opacity 0.3s';
  }
});

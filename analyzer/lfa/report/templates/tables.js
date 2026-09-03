// Vanilla JS table filter and tab switching
function initReportInteractive() {
  const searchInput = document.getElementById('event-filter');
  const table = document.getElementById('events-table');
  if (searchInput && table) {
    searchInput.addEventListener('keyup', () => {
      const filter = searchInput.value.toLowerCase();
      const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
      for (let i = 0; i < rows.length; i++) {
        const text = rows[i].textContent.toLowerCase();
        rows[i].style.display = text.indexOf(filter) > -1 ? '' : 'none';
      }
    });
  }

  // Tab switching logic for Forensic Intel
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const targetEl = targetId ? document.getElementById(targetId) : null;
      if (!targetEl) return;

      // Remove active from all
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      // Add active to clicked
      btn.classList.add('active');
      targetEl.classList.add('active');
    });
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initReportInteractive);
} else {
  initReportInteractive();
}

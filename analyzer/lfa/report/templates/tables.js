// Vanilla JS table filter and sorting
document.addEventListener('DOMContentLoaded', () => {
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
});

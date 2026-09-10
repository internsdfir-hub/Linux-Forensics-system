/* Report interactivity.
 *
 * Progressive enhancement only: every row is already in the HTML. This adds
 * sorting and filtering on top. With JavaScript disabled the report is still
 * complete and readable, which matters because it may be opened from
 * read-only media or a locked-down viewer.
 *
 * Wrapped in an IIFE so it introduces no globals.
 */
(function () {
  "use strict";

  /* ------------------------------------------------------------ sorting */

  function cellText(row, index) {
    var cell = row.children[index];
    return cell ? cell.textContent.trim() : "";
  }

  function comparator(index, kind, direction) {
    var sign = direction === "descending" ? -1 : 1;
    return function (a, b) {
      var x = cellText(a, index);
      var y = cellText(b, index);
      if (kind === "number") {
        var nx = parseFloat(x.replace(/[^0-9.-]/g, ""));
        var ny = parseFloat(y.replace(/[^0-9.-]/g, ""));
        nx = isNaN(nx) ? -Infinity : nx;
        ny = isNaN(ny) ? -Infinity : ny;
        return (nx - ny) * sign;
      }
      return x.localeCompare(y, undefined, { numeric: true }) * sign;
    };
  }

  function sortBy(table, header) {
    var headers = Array.prototype.slice.call(
      table.querySelectorAll("thead th")
    );
    var index = headers.indexOf(header);
    if (index < 0) return;

    var current = header.getAttribute("aria-sort");
    var direction = current === "ascending" ? "descending" : "ascending";

    headers.forEach(function (h) {
      h.removeAttribute("aria-sort");
    });
    header.setAttribute("aria-sort", direction);

    var body = table.tBodies[0];
    if (!body) return;
    var rows = Array.prototype.slice.call(body.rows);
    rows.sort(comparator(index, header.getAttribute("data-sort"), direction));
    rows.forEach(function (row) {
      body.appendChild(row);
    });
  }

  function enableSorting(table) {
    table.querySelectorAll("thead th[data-sort]").forEach(function (header) {
      header.setAttribute("tabindex", "0");
      header.setAttribute("role", "columnheader");

      header.addEventListener("click", function () {
        sortBy(table, header);
      });
      header.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          sortBy(table, header);
        }
      });
    });
  }

  /* ---------------------------------------------------------- filtering */

  function enableFiltering(input) {
    var table = document.getElementById(input.getAttribute("data-filters"));
    if (!table || !table.tBodies[0]) return;

    var body = table.tBodies[0];
    var rows = Array.prototype.slice.call(body.rows);
    var haystacks = rows.map(function (row) {
      return row.textContent.toLowerCase();
    });

    var status = document.createElement("p");
    status.className = "muted table-tools__status";
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    input.parentNode.appendChild(status);

    var timer = null;

    function apply() {
      var needle = input.value.trim().toLowerCase();
      var shown = 0;
      for (var i = 0; i < rows.length; i++) {
        var match = needle === "" || haystacks[i].indexOf(needle) !== -1;
        rows[i].hidden = !match;
        if (match) shown++;
      }
      status.textContent =
        needle === ""
          ? ""
          : shown + " of " + rows.length + " row(s) match “" + input.value + "”";
    }

    input.addEventListener("input", function () {
      /* Debounced: the event table can carry 1,500 rows and filtering on
         every keystroke makes typing feel broken. */
      if (timer) window.clearTimeout(timer);
      timer = window.setTimeout(apply, 120);
    });
  }

  /* --------------------------------------------------------------- init */

  function init() {
    document.querySelectorAll("table[data-sortable]").forEach(enableSorting);
    document.querySelectorAll("input[data-filters]").forEach(enableFiltering);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

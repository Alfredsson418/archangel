// Adds dragging and move buttons to a chain's rules. Everything here only
// rearranges the hidden fields of a form that the server validates, and the
// organize page works without this script through its single-rule form.
(function () {
  "use strict";

  function setUp(container) {
    const list = container.querySelector("[data-order-list]");
    const save = container.querySelector("[data-order-save]");
    const status = container.querySelector("[data-order-status]");
    if (!list || !save || !status) {
      return;
    }

    const rows = () => Array.from(list.querySelectorAll("[data-order-row]"));
    const orderOf = () => rows().map((row) => row.querySelector('input[name="order"]').value);
    const original = orderOf().join("\n");

    function refresh(announcement) {
      rows().forEach((row, index) => {
        row.querySelector("[data-order-position]").textContent = String(index + 1);
      });
      const changed = orderOf().join("\n") !== original;
      save.hidden = !changed;
      status.hidden = !changed && !announcement;
      status.textContent = announcement || "The order has changed. It isn't applied until you add it to pending changes and confirm it.";
    }

    list.addEventListener("click", (event) => {
      const button = event.target.closest("button[data-move]");
      if (!button) {
        return;
      }
      const row = button.closest("[data-order-row]");
      const moveUp = button.dataset.move === "up";
      const sibling = moveUp ? row.previousElementSibling : row.nextElementSibling;
      if (!sibling) {
        return;
      }
      list.insertBefore(row, moveUp ? sibling : sibling.nextElementSibling);
      button.focus();
      refresh(`Moved to position ${rows().indexOf(row) + 1} of ${rows().length}. Not applied yet.`);
    });

    container.querySelectorAll("[data-order-buttons], [data-drag-handle], [data-order-hint]").forEach((element) => {
      element.hidden = false;
    });

    if (window.Sortable) {
      window.Sortable.create(list, {
        animation: 120,
        // Pointer events behave the same for table rows, mouse, and touch,
        // which the browser's native drag events don't.
        forceFallback: true,
        handle: "[data-drag-handle]",
        draggable: "[data-order-row]",
        onEnd: () => refresh(),
      });
    }
  }

  document.querySelectorAll("[data-rule-order]").forEach(setUp);
})();

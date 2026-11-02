// Adds dragging and move buttons to the organize page. Everything here only
// rearranges the form's hidden fields: the server validates the submitted order,
// and the page works without this script through its single-rule form.
(function () {
  "use strict";

  const list = document.getElementById("rule-order-list");
  const save = document.getElementById("order-save");
  const status = document.getElementById("order-status");
  if (!list || !save || !status) {
    return;
  }

  const rows = () => Array.from(list.querySelectorAll(".rule-order-row"));
  const orderOf = () => rows().map((row) => row.querySelector('input[name="order"]').value);
  const original = orderOf().join("\n");

  function refresh(announcement) {
    rows().forEach((row, index) => {
      row.querySelector(".rule-order-position").textContent = String(index + 1);
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
    const row = button.closest(".rule-order-row");
    const sibling = button.dataset.move === "up" ? row.previousElementSibling : row.nextElementSibling;
    if (!sibling) {
      return;
    }
    list.insertBefore(row, button.dataset.move === "up" ? sibling : sibling.nextElementSibling);
    button.focus();
    const position = rows().indexOf(row) + 1;
    refresh(`Moved to position ${position} of ${rows().length}. Not applied yet.`);
  });

  document.querySelectorAll(".rule-order-move, .drag-handle").forEach((element) => {
    element.hidden = false;
  });

  if (window.Sortable) {
    window.Sortable.create(list, {
      animation: 120,
      handle: ".drag-handle",
      onEnd: () => refresh(),
    });
  }
})();

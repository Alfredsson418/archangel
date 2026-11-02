// Remembers which branches of the rules tree are open, and adds buttons to open
// or close them all. The tree itself is native HTML and works without this.
(function () {
  "use strict";

  const STORAGE_KEY = "archangel-rule-tree";
  const tree = document.querySelector("[data-rule-tree]");
  if (!tree) {
    return;
  }
  const branches = () => Array.from(tree.querySelectorAll("details[data-tree-id]"));

  function saved() {
    try {
      return JSON.parse(window.localStorage.getItem(STORAGE_KEY)) || {};
    } catch (error) {
      return {};
    }
  }

  function remember() {
    const state = {};
    branches().forEach((branch) => {
      state[branch.dataset.treeId] = branch.open;
    });
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch (error) {
      // Only a convenience, so a browser that refuses storage just forgets.
    }
  }

  // A filter or a just-applied change decides what should be open this time.
  if (tree.dataset.keepOpenState !== "false") {
    const state = saved();
    branches().forEach((branch) => {
      if (Object.prototype.hasOwnProperty.call(state, branch.dataset.treeId)) {
        branch.open = state[branch.dataset.treeId];
      }
    });
  }
  tree.addEventListener("toggle", remember, true);

  document.querySelectorAll("[data-tree-all]").forEach((button) => {
    button.hidden = false;
    button.addEventListener("click", () => {
      const open = button.dataset.treeAll === "open";
      // Management forms stay as they are, so that the tree stays readable.
      branches()
        .filter((branch) => !branch.classList.contains("tree-manage"))
        .forEach((branch) => {
          branch.open = open;
        });
    });
  });
})();

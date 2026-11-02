// Adds Expand all and Minimize all to the file tree, and remembers what's open
// in this browser. The tree itself is native HTML and works without this.
(function () {
  "use strict";

  const STORAGE_KEY = "archangel-file-tree";
  const tree = document.querySelector("[data-file-tree]");
  if (!tree) {
    return;
  }
  const branches = () => Array.from(tree.querySelectorAll("details[data-branch]"));

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
      state[branch.dataset.branch] = branch.open;
    });
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch (error) {
      // Only a convenience, so a browser that refuses storage just forgets.
    }
  }

  // A filter decides what's shown this time, and the selection always stays
  // visible, whatever was remembered.
  if (tree.dataset.remember !== "false") {
    const state = saved();
    branches().forEach((branch) => {
      if (Object.prototype.hasOwnProperty.call(state, branch.dataset.branch)) {
        branch.open = state[branch.dataset.branch] || branch.hasAttribute("data-selected");
      }
    });
  }

  // Remembers only what a person does, not the page opening branches on load.
  tree.addEventListener("click", (event) => {
    if (event.target.closest("summary")) {
      window.setTimeout(remember, 0);
    }
  });

  tree.querySelectorAll("[data-tree-all]").forEach((button) => {
    button.hidden = false;
    button.addEventListener("click", () => {
      const open = button.dataset.treeAll === "open";
      branches().forEach((branch) => {
        branch.open = open;
      });
      remember();
    });
  });
})();

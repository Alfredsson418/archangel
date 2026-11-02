"""Drive the dashboard in a real browser, against the real API and nftables.

The drag-and-drop script can't be tested any other way. Everything runs in a
private network namespace, so it never touches the host's firewall:

    unshare -rn dashboard/.venv/bin/python dashboard/tests/integration/browser_namespace.py [screenshot-directory]

Requires a debug build at bin/archangel, and Playwright with Chromium:

    dashboard/.venv/bin/python -m pip install playwright
    dashboard/.venv/bin/python -m playwright install chromium-headless-shell

The script refuses to run unless it is root inside a new user namespace.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from changes_namespace import PASSWORD, USERNAME, create_dashboard, listed, require_isolation, start_backend  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402


WEB_PORT = 18090
WEB = f"http://127.0.0.1:{WEB_PORT}"
FIREWALL = """
table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    ct state established,related accept
    iifname "lo" accept
    tcp dport 22 accept
    meta l4proto icmp accept
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
    iifname "wg0" oifname "eth0" accept
  }
  chain work {
    tcp dport 1001 accept comment "archangel-managed"
    tcp dport 1002 accept comment "archangel-managed"
    tcp dport 1003 accept comment "archangel-managed"
    tcp dport 1004 accept comment "archangel-managed"
  }
  chain empty {
  }
}
table ip nat {
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    oifname "eth0" masquerade
  }
}
table ip6 filter6 {
  chain input6 {
    type filter hook input priority 0; policy accept;
    meta l4proto ipv6-icmp accept
  }
}
"""


class Failures(list):
    def check(self, condition, message):
        print(f"{'ok  ' if condition else 'FAIL'} {message}")
        if not condition:
            self.append(message)


def work_ports():
    listing = json.loads(subprocess.run(["nft", "-j", "list", "chain", "inet", "filter", "work"], check=True, capture_output=True, text=True).stdout)
    return [entry["rule"]["expr"][0]["match"]["right"] for entry in listing["nftables"] if "rule" in entry]


def row_text(page):
    return [text.split("to port ")[1].split()[0] for text in page.locator('[data-chain="inet filter work"] tbody tr').all_inner_texts()]


def drag(page, source, target):
    """Drag with real mouse events, which is what SortableJS listens for."""
    # The mouse can only reach what's on screen.
    target.scroll_into_view_if_needed()
    source.scroll_into_view_if_needed()
    start = source.bounding_box()
    end = target.bounding_box()
    page.mouse.move(start["x"] + start["width"] / 2, start["y"] + start["height"] / 2)
    page.mouse.down()
    page.mouse.move(start["x"] + start["width"] / 2, start["y"] + start["height"] / 2 + 4, steps=3)
    page.mouse.move(end["x"] + end["width"] / 2, end["y"] + end["height"] / 2 + 6, steps=20)
    time.sleep(0.25)
    page.mouse.up()
    time.sleep(0.25)


def main():
    require_isolation()
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    shots = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    directory = Path(tempfile.mkdtemp(prefix="archangel-browser-"))
    directory.chmod(0o700)
    failures = Failures()
    backend = start_backend(directory)
    try:
        subprocess.run(["nft", "-f", "-"], input=FIREWALL, text=True, check=True, capture_output=True)
        client = create_dashboard(directory)
        app = client.application
        threading.Thread(target=lambda: app.run(host="127.0.0.1", port=WEB_PORT, threaded=True, use_reloader=False), daemon=True).start()
        time.sleep(1)

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(args=["--no-sandbox"])
            context = browser.new_context(viewport={"width": 1280, "height": 1000})
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
            external = []
            page.on("request", lambda request: external.append(request.url) if not request.url.startswith(WEB) else None)

            def shot(name):
                if shots:
                    page.screenshot(path=str(shots / f"{name}.png"), full_page=True)

            print("-- signing in and seeing the tree")
            page.goto(f"{WEB}/login")
            page.fill('input[name="username"]', USERNAME)
            page.fill('input[name="password"]', PASSWORD)
            page.click('button[type="submit"]')
            page.goto(f"{WEB}/rules")
            shot("tree")
            failures.check(page.locator('[data-nav="family:inet"]').is_visible(), "the tree shows the family")
            failures.check(page.locator('[data-nav="table:ip nat"]').is_visible(), "the tree shows other tables")
            failures.check(page.locator('[data-chain="inet filter work"] tbody tr').count() == 4, "the first table's chains are open")
            failures.check(page.locator('[data-nav="chain:inet filter work"]').is_visible(), "its chains are listed in the tree")
            failures.check(page.locator('[data-chain="ip nat postrouting"]').count() == 0, "other tables' chains aren't shown")
            failures.check(external == [], f"nothing loads from other sites: {external[:2]}")

            def overlaps(locator):
                """Report whether a rule's text runs into its actions."""
                return locator.evaluate(
                    """row => {
                        const text = row.querySelector('.rule-col-text');
                        const range = document.createRange();
                        range.selectNodeContents(text);
                        const content = range.getBoundingClientRect();
                        const actions = row.querySelector('.rule-actions').getBoundingClientRect();
                        return content.right > actions.left && content.bottom > actions.top && content.top < actions.bottom;
                    }"""
                )

            print("-- navigating the file tree")
            page.click('[data-nav="table:ip nat"]')
            failures.check(page.locator('[data-chain="ip nat postrouting"]').is_visible(), "selecting a table opens its chain")
            failures.check(page.locator('[data-nav="chain:ip nat postrouting"]').is_visible(), "its chain appears in the tree")
            failures.check(page.locator('[data-nav="chain:ip nat postrouting"]').is_visible(), "the selected table stays open in the tree")
            failures.check(page.locator('[data-nav="table:ip nat"]').get_attribute("aria-current") == "page", "the selection is marked")
            shot("table-selected")
            raw = page.locator('[data-chain="ip nat postrouting"] tbody tr').first
            failures.check("masquerade" in raw.inner_text() and not overlaps(raw), "a long raw rule wraps instead of covering its actions")
            page.reload()
            failures.check(page.locator('[data-chain="ip nat postrouting"]').is_visible(), "the selection survives a reload")
            page.click('[data-nav="table:inet filter"]')
            page.click('[data-nav="chain:inet filter work"]')
            failures.check(page.locator("[data-chain]").count() == 1, "selecting a chain shows only that chain")
            shot("chain-selected")
            page.click('.detail-path a')
            failures.check(page.locator("[data-chain]").count() == 4, "the path goes back to the table")
            page.click('[data-branch="table:ip nat"] > summary', position={"x": 8, "y": 10}) if not page.locator('[data-nav="table:ip nat"]').is_visible() else None
            page.focus('[data-nav="table:ip nat"]')
            page.keyboard.press("Enter")
            page.wait_for_url("**table=nat**")
            failures.check(True, "the tree works with the keyboard")
            page.click('[data-nav="table:inet filter"]')

            print("-- expanding and minimizing the tree")
            page.goto(f"{WEB}/rules?family=inet&table=filter")
            nat_chain = page.locator('[data-nav="chain:ip nat postrouting"]')
            failures.check(not nat_chain.is_visible(), "other tables start closed")
            page.click('[data-tree-all="open"]')
            failures.check(nat_chain.is_visible(), "expand all opens every table")
            failures.check(not page.locator('[data-new-chain="inet filter"] form').is_visible(), "expand all leaves the new-entry forms closed")
            shot("expanded")
            page.reload()
            failures.check(nat_chain.is_visible(), "the tree remembers what's open")
            page.click('[data-tree-all="close"]')
            failures.check(not page.locator('[data-nav="table:inet filter"]').is_visible(), "minimize all closes every family")
            shot("minimized")
            page.reload()
            failures.check(page.locator('[data-nav="chain:inet filter input"]').is_visible(), "the selected table reopens after a reload")
            failures.check(not nat_chain.is_visible(), "other tables stay minimized")
            page.click('[data-tree-all="open"]')
            page.click('[data-tree-all="close"]')
            page.click('[data-branch="family:inet"] > summary')
            page.click('[data-branch="table:inet filter"] > summary', position={"x": 8, "y": 12})
            failures.check(page.locator('[data-nav="chain:inet filter input"]').is_visible(), "a branch opens by its arrow without navigating")
            page.goto(f"{WEB}/rules?family=inet&table=filter")

            print("-- appending from the last entry of a list")
            chains = page.locator('[data-branch="table:inet filter"] > ul > li')
            failures.check("New chain" in chains.last.inner_text(), "+ New chain is the last entry of the table")
            tables = page.locator('[data-branch="family:inet"] > ul > li')
            failures.check("New table" in tables.last.inner_text(), "+ New table is the last entry of the family")
            new_chain = page.locator('[data-new-chain="inet filter"]')
            new_chain.locator("summary").click()
            shot("new-chain")
            new_chain.locator('input[name="name"]').fill("added")
            new_chain.locator('button[name="structure_action"]').click()
            page.wait_for_url("**/changes")
            failures.check("New chain" in page.content(), "it adds a pending change")
            failures.check("chain added" not in listed(), "the firewall hasn't changed")
            page.goto(f"{WEB}/rules?family=inet&table=filter")
            # The tree remembers being minimized above, so open it as a person would.
            page.click('[data-tree-all="open"]')
            new_table = page.locator('[data-new-table="ip"]')
            new_table.locator("summary").click()
            new_table.locator('input[name="name"]').fill("appended")
            new_table.locator('button[name="structure_action"]').click()
            page.wait_for_url("**/changes")
            page.check('input[name="confirm"]')
            page.click('button:has-text("Apply")')
            page.wait_for_url("**/rules")
            rules = listed()
            failures.check("chain added" in rules and "table ip appended" in rules, "applying creates them in the right places")
            subprocess.run(["nft", "delete", "chain", "inet", "filter", "added"], check=True)
            subprocess.run(["nft", "delete", "table", "ip", "appended"], check=True)
            page.goto(f"{WEB}/rules?family=inet&table=filter")

            print("-- seeing the hierarchy")
            left = lambda selector: page.locator(selector).bounding_box()["x"]
            family_left = left('[data-branch="family:inet"] .file-tree-family-name')
            table_left = left('[data-nav="table:inet filter"]')
            chain_left = left('[data-nav="chain:inet filter input"]')
            failures.check(family_left + 10 < table_left < chain_left - 10, f"each level is indented further: {family_left:.0f}, {table_left:.0f}, {chain_left:.0f}")
            page.click('[data-nav="chain:inet filter input"]')
            failures.check(page.locator("[data-narrowed]").is_visible(), "a narrowed view says so")
            page.reload()
            failures.check(page.locator("[data-narrowed]").is_visible(), "it still says so when remembered")
            page.click('[data-narrowed] a')
            failures.check(page.locator("[data-chain]").count() == 4, "it can show every chain again")

            print("-- collapsing a chain")
            work = page.locator('[data-chain="inet filter work"]')
            work.locator("summary").first.click()
            failures.check(not work.locator("tbody").is_visible(), "a chain collapses")
            work.locator("summary").first.click()
            failures.check(work.locator("tbody").is_visible(), "and opens again")
            failures.check(not work.locator(".tree-manage-body").is_visible(), "management forms start closed")

            print("-- finding and using the drag handle")
            handles = work.locator("[data-drag-handle]")
            failures.check(handles.count() == 4 and handles.first.is_visible(), "drag handles are visible on the rules")
            failures.check(work.locator("[data-order-hint]").is_visible(), "a hint explains them")
            save = work.locator("[data-order-save]")
            failures.check(not save.is_visible(), "there's nothing to save yet")
            shot("handles")
            drag(page, handles.nth(3), handles.nth(0))
            failures.check(row_text(page)[0] == "1004", f"dragging moves the rule: {row_text(page)}")
            failures.check(work.locator("[data-order-position]").first.inner_text() == "1", "positions renumber")
            failures.check(save.is_visible(), "the save button appears")
            failures.check(work_ports() == [1001, 1002, 1003, 1004], "the firewall hasn't changed")
            shot("dragged")

            print("-- saving, reviewing, and applying the drag")
            save.click()
            page.wait_for_url("**/changes")
            shot("review")
            failures.check("not applied yet" not in page.content(), "the review page doesn't link to itself")
            failures.check("Rule order" in page.content() and "position 4" in page.content(), "the review shows the moves")
            failures.check(work_ports() == [1001, 1002, 1003, 1004], "the firewall still hasn't changed")
            page.check('input[name="confirm"]')
            page.click('button:has-text("Apply")')
            page.wait_for_url("**/rules")
            failures.check(work_ports() == [1004, 1001, 1002, 1003], f"nftables has the new order: {work_ports()}")
            failures.check(row_text(page) == ["1004", "1001", "1002", "1003"], "the tree shows the result")

            print("-- the arrow buttons, for keyboards")
            first = page.locator('[data-chain="inet filter work"] tbody tr').first
            first.locator('button[data-move="down"]').click()
            failures.check(row_text(page)[:2] == ["1001", "1004"], f"moving down works: {row_text(page)}")
            failures.check(page.evaluate("document.activeElement.dataset.move") == "down", "focus stays on the button")
            failures.check("position 2 of 4" in work.locator("[data-order-status]").inner_text(), "the move is announced")
            page.keyboard.press("Enter")
            failures.check(row_text(page)[:3] == ["1001", "1002", "1004"], "the keyboard can repeat it")
            page.reload()
            failures.check(row_text(page)[0] == "1004", "leaving discards an unsaved order")

            print("-- the organize page, when a chain has pending changes")
            page.goto(f"{WEB}/rules/new?chain=inet+filter+work")
            page.fill('input[name="destination_port"]', "1005")
            page.select_option('select[name="protocol"]', "tcp")
            page.click('button:has-text("Add to pending changes")')
            page.wait_for_url("**/changes")
            page.goto(f"{WEB}/rules")
            failures.check(work.locator("[data-drag-handle]").count() == 0, "dragging in place isn't offered")
            work.locator('a:has-text("Reorder rules")').click()
            page.wait_for_url("**/rules/organize*")
            shot("organize")
            handles = page.locator("[data-drag-handle]")
            failures.check(handles.count() == 5, "the page includes the pending new rule")
            failures.check("PENDING NEW RULE" in page.content(), "the new rule is labelled")
            drag(page, handles.nth(4), handles.nth(0))
            page.locator("[data-order-save]").click()
            page.wait_for_url("**/changes")
            page.check('input[name="confirm"]')
            page.click('button:has-text("Apply")')
            page.wait_for_url("**/rules")
            failures.check(work_ports()[0] == 1005 and len(work_ports()) == 5, f"the new rule landed first: {work_ports()}")

            print("-- managing the tree")
            work.locator('.tree-manage > summary').click()
            shot("manage")
            work.locator('input[name="new_name"]').fill("renamed")
            work.locator('button:has-text("Rename")').click()
            page.wait_for_url("**/changes")
            page.check('input[name="confirm"]')
            page.click('button:has-text("Apply")')
            page.wait_for_url("**/rules")
            failures.check("chain renamed" in listed(), "a chain can be renamed from the tree")

            print("-- on a phone")
            phone = browser.new_context(viewport={"width": 390, "height": 800}, has_touch=True, storage_state=context.storage_state())
            small = phone.new_page()
            small.goto(f"{WEB}/rules?family=inet&table=filter")
            if shots:
                small.screenshot(path=str(shots / "phone.png"), full_page=True)
            width = small.evaluate("document.documentElement.scrollWidth")
            failures.check(width <= 390, f"the page doesn't scroll sideways: {width}px")
            delete = small.locator('[data-chain="inet filter input"] button:has-text("Delete")').first
            box = delete.bounding_box()
            failures.check(box and box["x"] + box["width"] <= 390, "a rule's actions are on screen without scrolling")
            touch_handle = small.locator('[data-chain="inet filter input"] [data-drag-handle]').first
            failures.check(touch_handle.is_visible(), "drag handles are available")
            tree_box = small.locator(".file-tree").bounding_box()
            detail_box = small.locator(".rules-detail").bounding_box()
            failures.check(tree_box["y"] + tree_box["height"] <= detail_box["y"] + 1, "the tree stacks above the chains")
            small.goto(f"{WEB}/rules?family=ip&table=nat")
            scrolling = small.locator('[data-chain="ip nat postrouting"] .tree-rules-wrap').evaluate("wrap => wrap.scrollWidth > wrap.clientWidth")
            failures.check(not scrolling, "a long raw rule wraps too")
            phone.close()

            print("-- without JavaScript")
            plain = browser.new_context(java_script_enabled=False, storage_state=context.storage_state())
            nojs = plain.new_page()
            nojs.goto(f"{WEB}/rules?family=inet&table=filter")
            failures.check(nojs.locator("[data-drag-handle]").first.is_hidden(), "handles stay hidden")
            failures.check(nojs.locator('[data-tree-all="open"]').is_hidden(), "the tree buttons stay hidden, since they'd do nothing")
            nojs.click('[data-branch="table:ip nat"] > summary', position={"x": 8, "y": 10})
            nojs.click('[data-nav="table:ip nat"]')
            failures.check(nojs.locator('[data-chain="ip nat postrouting"]').is_visible(), "the file tree still works")
            nojs.goto(f"{WEB}/rules/organize?chain=inet+filter+renamed")
            failures.check(nojs.locator("[data-order-buttons]").first.is_hidden(), "the arrows stay hidden, since they'd do nothing")
            nojs.select_option('select[name="move_rule"]', index=2)
            nojs.fill('input[name="move_position"]', "1")
            nojs.click('button:has-text("Move and add")')
            nojs.wait_for_url("**/changes")
            failures.check("Rule order" in nojs.content(), "the single-rule form works")
            plain.close()

            failures.check(not errors, f"the browser reported no errors: {errors[:3]}")
            browser.close()
        print(f"{len(failures)} failures")
        return 1 if failures else 0
    finally:
        backend.terminate()
        backend.wait()
        shutil.rmtree(directory, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

import os
import tempfile


os.environ.setdefault("ARCHANGEL_DEV_MODE", "true")
# The app is created when tests import server; keep its audit log in a private
# temporary directory rather than the container's /data volume.
os.environ.setdefault(
    "ARCHANGEL_WEB_LOG_PATH",
    os.path.join(tempfile.mkdtemp(prefix="archangel-web-test-"), "archangel-frontend.jsonl"),
)

from __future__ import annotations

import app_v402
import app

APP_VERSION = "5.0.0"

# Promote the fully patched V4.0.2 claimant-only scanner into a clean V5
# application identity. The imported verification function reads the module
# version dynamically, so audits and the window report V5 consistently.
app_v402.APP_VERSION = APP_VERSION
app.APP_VERSION = APP_VERSION

if __name__ == "__main__":
    app.PIIScrubberApp().mainloop()

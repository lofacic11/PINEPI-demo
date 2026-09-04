from __future__ import annotations

import os
import signal

from . import create_app


def main() -> None:
    app = create_app()
    operations = app.extensions["operations"]

    def stop(_signum, _frame) -> None:
        operations.shutdown()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    app.run(
        host=os.getenv("PINEPI_HOST", "0.0.0.0"),
        port=int(os.getenv("PINEPI_PORT", "8080")),
        threaded=True,
        use_reloader=False,
    )


if __name__ == "__main__":
    main()

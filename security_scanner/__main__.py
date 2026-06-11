"""Module entrypoint for `python -m security_scanner`."""

from security_scanner.cli import main

# Convert the CLI return code into the process exit code.
raise SystemExit(main())

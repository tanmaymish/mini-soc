"""Enable `python -m cli ...`."""

import sys

from cli.soc import main

if __name__ == "__main__":
    sys.exit(main())

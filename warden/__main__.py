"""Enable ``python -m warden`` (used by scheduled tasks and packaged builds)."""

from .cli import main

if __name__ == "__main__":
    main()

"""PyInstaller entry point. A thin wrapper so the frozen binary runs the CLI."""

from warden.cli import main

if __name__ == "__main__":
    main()

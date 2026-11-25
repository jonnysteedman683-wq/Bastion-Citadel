"""Main entry point for Bastion-Citadel."""

import asyncio
import sys

from bastion_citadel.cli.main import main


if __name__ == "__main__":
    asyncio.run(main())

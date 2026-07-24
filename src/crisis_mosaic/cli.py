from __future__ import annotations

import argparse
import asyncio
import json

import uvicorn

from .config import get_settings
from .db import dispose_database
from .seed import seed_demo


def main() -> None:
    parser = argparse.ArgumentParser(prog="crisis-mosaic")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("seed", help="idempotently create the Hangzhou demo")
    serve = subparsers.add_parser("serve", help="run the single-process API")
    serve.add_argument("--reload", action="store_true")
    args = parser.parse_args()
    settings = get_settings()
    if args.command == "seed":

        async def run_seed() -> None:
            try:
                result = await seed_demo()
                print(json.dumps(result, ensure_ascii=False, indent=2))
            finally:
                await dispose_database()

        asyncio.run(run_seed())
        return
    uvicorn.run(
        "crisis_mosaic.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=args.reload,
        workers=1,
        log_level=settings.app_log_level.lower(),
    )


if __name__ == "__main__":
    main()

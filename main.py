"""
Crucible service entry point.

Starts the FastAPI server with uvicorn.

Usage:
    python main.py
    python main.py --host 0.0.0.0 --port 8420
    uvicorn api.server:app --reload   (for development)
"""

import argparse
import os

from dotenv import load_dotenv

load_dotenv()


def main():
    parser = argparse.ArgumentParser(description="Crucible — secure code execution service")
    parser.add_argument(
        "--host",
        default=os.getenv("CRUCIBLE_HOST", "0.0.0.0"),
        help="Bind host (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("CRUCIBLE_PORT", "8420")),
        help="Bind port (default: 8420)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload (development only)",
    )
    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        print("uvicorn not installed. Run: pip install uvicorn[standard]")
        raise SystemExit(1)

    print(f"Starting Crucible on http://{args.host}:{args.port}")
    print("Docs: http://localhost:8420/docs")
    print("Press Ctrl+C to stop.\n")

    uvicorn.run(
        "api.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()

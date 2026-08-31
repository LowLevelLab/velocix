"""Velocix CLI - Built-in development server using granian"""

import asyncio
import platform
import sys

import click
from granian.log import LogLevels


def optimize_for_platform():
    """
    Apply platform-specific optimizations for best performance.
    Windows-safe: Only uses optimizations that work on Windows.
    """
    system = platform.system()

    if system == "Windows":
        # Windows-specific optimizations
        # Use ProactorEventLoop for better I/O performance
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())  # type: ignore[attr-defined]
        click.echo("✅ Windows: Using ProactorEventLoop for optimal I/O")
    elif system in ("Linux", "Darwin"):
        # Linux/macOS: Try to use uvloop if available
        try:
            import uvloop

            uvloop.install()
            click.echo(f"✅ {system}: Using uvloop for 2-4x faster I/O")
        except ImportError:
            click.echo(
                f"ℹ️  {system}: uvloop not available (pip install uvloop for better performance)"
            )

    return system


@click.command()
@click.argument("app", required=True)
@click.option("--host", default="127.0.0.1", help="Host to bind")
@click.option("--port", default=8000, type=int, help="Port to bind")
@click.option("--workers", "-w", default=1, type=int, help="Number of worker processes")
@click.option("--threads", "-t", default=1, type=int, help="Number of threads per worker")
@click.option("--reload", is_flag=True, help="Enable auto-reload on code changes")
@click.option(
    "--interface", default="asgi", type=click.Choice(["asgi", "wsgi"]), help="Application interface"
)
@click.option(
    "--log-level",
    default="info",
    type=click.Choice(["critical", "error", "warning", "info", "debug"]),
    help="Log level",
)
@click.option(
    "--backlog", default=2048, type=int, help="Maximum number of connections to hold in backlog"
)
@click.option("--blocking-threads", default=None, type=int, help="Number of blocking threads")
@click.option("--websockets/--no-websockets", default=True, help="Enable WebSocket support")
@click.option(
    "--optimize/--no-optimize", default=True, help="Enable platform-specific optimizations"
)
def run(
    app: str,
    host: str,
    port: int,
    workers: int,
    threads: int,
    reload: bool,
    interface: str,
    log_level: str,
    backlog: int,
    blocking_threads: int | None,
    websockets: bool,
    optimize: bool,
) -> None:
    """
    Run Velocix application with granian ASGI server

    Examples:
        velocix run server:app
        velocix run server:app --reload
        velocix run server:app --workers 4 --threads 2
        velocix run server:app --host 0.0.0.0 --port 8080
        velocix run server:app --no-optimize  # Disable optimizations
    """
    try:
        from granian import Granian
        from granian.constants import Interfaces, Loops
    except ImportError:
        click.echo("ERROR: granian not installed. Install it with: pip install granian", err=True)
        sys.exit(1)

    # Apply platform optimizations
    if optimize:
        optimize_for_platform()

    # Parse app path
    if ":" not in app:
        click.echo("ERROR: Invalid app format. Use: module:app (e.g., server:app)", err=True)
        sys.exit(1)

    # Convert interface string to enum
    interface_map = {
        "asgi": Interfaces.ASGI,
        "asgi-ws": Interfaces.ASGI,  # granian auto-detects WebSocket
        "wsgi": Interfaces.WSGI,
    }

    # Determine optimal loop implementation for platform
    loop_impl = Loops.asyncio  # Windows-safe default
    if optimize and platform.system() in ("Linux", "Darwin"):
        try:
            import uvloop  # noqa: F401

            loop_impl = Loops.uvloop
        except ImportError:
            pass

    # Banner
    click.echo("Starting Velocix")
    click.echo(f"Application: {app}")
    click.echo(f"Listening: http://{host}:{port}")
    click.echo(f"Workers: {workers}")
    if blocking_threads:
        click.echo(f"Blocking threads: {blocking_threads}")
    if reload:
        click.echo("Auto-reload: enabled")
    if optimize:
        click.echo(f"Loop: {loop_impl.name}")
    click.echo("")

    # Create granian instance with Windows-compatible optimizations
    log_level_enum = LogLevels(log_level)

    # Build Granian parameters (threads parameter depends on version)
    granian_params = {
        "target": app,
        "address": host,
        "port": port,
        "interface": interface_map[interface],
        "loop": loop_impl,
        "workers": workers,
        "reload": reload,
        "log_level": log_level_enum,
        "backlog": backlog,
        "websockets": websockets,
        "http": "auto",
    }

    # Add threads if supported by granian version
    if blocking_threads is not None:
        granian_params["blocking_threads"] = blocking_threads

    # Note: 'threads' parameter was removed in newer granian versions
    # Use 'blocking_threads' instead for thread pool size

    # granian_params is built conditionally (blocking_threads is optional), so
    # mypy can't match a plain dict[str, object] against Granian's many
    # distinct keyword-argument types.
    server = Granian(**granian_params)  # type: ignore[arg-type]

    try:
        server.serve()
    except KeyboardInterrupt:
        click.echo("\nShutting down...")


@click.group()
def cli() -> None:
    """Velocix - High-performance Python web framework"""
    pass


cli.add_command(run)


if __name__ == "__main__":
    cli()

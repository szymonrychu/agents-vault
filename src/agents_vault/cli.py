"""argparse front end with a command registry."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence

from agents_vault import __version__
from agents_vault.settings import Settings, SettingsError, load_settings

EXIT_CONFIG = 78

CommandFunc = Callable[[argparse.Namespace], int | None]

ConfigureFunc = Callable[[argparse.ArgumentParser], None]

_COMMANDS: dict[str, tuple[CommandFunc, str, ConfigureFunc | None]] = {}


def register(
    name: str,
    func: CommandFunc,
    help: str,  # noqa: A002
    configure: ConfigureFunc | None = None,
) -> None:
    """Register a subcommand; func receives the parsed args and returns the exit code.

    `configure` adds the subcommand's own arguments to its parser.
    """
    _COMMANDS[name] = (func, help, configure)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vault", description="agents-vault")
    parser.add_argument("--version", action="version", version=f"vault {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    for name, (func, help_text, configure) in _COMMANDS.items():
        cmd = sub.add_parser(name, help=help_text)
        cmd.set_defaults(func=func)
        if configure is not None:
            configure(cmd)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if args.command is None:
        parser.print_help(sys.stderr)
        raise SystemExit(2)
    return int(args.func(args) or 0)


def _configured(func: Callable[[Settings], int | None]) -> CommandFunc:
    """Wrap a command that needs settings: a bad configuration prints each problem, exits 78."""

    def run(_: argparse.Namespace) -> int | None:
        try:
            settings = load_settings()
        except SettingsError as exc:
            for name, problem in exc.problems.items():
                print(f"{name}: {problem}", file=sys.stderr)
            return EXIT_CONFIG
        return func(settings)

    return run


def _migrate(settings: Settings) -> int:
    from agents_vault.db import migrate

    for name in migrate(settings):
        print(name)
    return 0


def _sweeper(settings: Settings) -> int:
    from agents_vault.sweeper import main as run

    return run(settings)


def _serve_web(settings: Settings) -> int:
    from agents_vault import runtime

    return runtime.web_main(settings)


def _service_tokens(settings: Settings) -> list[str]:
    """The orchestrator's service tokens; ValueError names the setting at fault, never a token."""
    from agents_common.service_gate import load_tokens

    if not settings.service_tokens_file:
        raise ValueError("VAULT_SERVICE_TOKENS_FILE: required to serve the service listener")
    try:
        tokens = load_tokens(settings.service_tokens_file)
    except (OSError, ValueError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc)
        raise ValueError(f"VAULT_SERVICE_TOKENS_FILE: {reason}") from None
    if settings.orchestrator_token.get_secret_value() in tokens:
        raise ValueError(
            "VAULT_SERVICE_TOKENS_FILE: service tokens must differ from VAULT_ORCHESTRATOR_TOKEN"
        )
    return tokens


def _serve_service(settings: Settings) -> int:
    from agents_vault import runtime

    try:
        tokens = _service_tokens(settings)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return EXIT_CONFIG
    return runtime.service_main(settings, tokens)


register("migrate", _configured(_migrate), "apply the schema migrations and exit")
register("serve-web", _configured(_serve_web), "serve the user-facing http api")
register("serve-service", _configured(_serve_service), "serve the orchestrator-facing http api")
register("sweeper", _configured(_sweeper), "release pins, collect versions, reap stale writes")


if __name__ == "__main__":
    raise SystemExit(main())

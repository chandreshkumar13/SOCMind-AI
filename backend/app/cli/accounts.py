"""Manage the accounts used in AUTH_MODE=accounts.

    python -m app.cli.accounts create-user --username NAME --role viewer|analyst|approver
    python -m app.cli.accounts disable-user --username NAME
    python -m app.cli.accounts enable-user --username NAME
    python -m app.cli.accounts list-users

Passwords are read with getpass, twice, and are never accepted as a command-line argument, from a file or from an environment
variable. Nothing here creates an account by default. The database is the one named by DATABASE_URL; its account tables are
created there if they do not exist yet. Neither a password nor a password hash is ever printed.
"""
import argparse
import getpass
import sys
from typing import Callable, Optional, Sequence

from app.db.session import SessionLocal, init_db
from app.services import accounts

ROLES = accounts.ROLES


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli.accounts", description="Manage SOCMind AI accounts.")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create-user", help="create an account (the password is asked for, not passed)")
    create.add_argument("--username", required=True)
    create.add_argument("--role", required=True, choices=ROLES)
    for name, text in (("disable-user", "disable an account and end its sessions"), ("enable-user", "enable a disabled account")):
        sub = commands.add_parser(name, help=text)
        sub.add_argument("--username", required=True)
    commands.add_parser("list-users", help="list accounts (no password data)")
    return parser


def main(argv: Optional[Sequence[str]] = None,
         read_password: Callable[[str], str] = getpass.getpass,
         out: Callable[[str], None] = print,
         err: Callable[[str], None] = lambda text: print(text, file=sys.stderr)) -> int:
    args = build_parser().parse_args(argv)
    init_db()
    db = SessionLocal()
    try:
        if args.command == "create-user":
            password = read_password("Password: ")
            if read_password("Repeat password: ") != password:
                err("The two passwords do not match. No account was created.")
                return 2
            user = accounts.create_user(db, args.username, args.role, password)
            out(f"Created the {user.role} account '{user.username}'.")
            return 0
        if args.command in ("disable-user", "enable-user"):
            user = accounts.set_active(db, args.username, active=args.command == "enable-user")
            out(f"The account '{user.username}' is now {'enabled' if user.is_active else 'disabled'}.")
            return 0
        if args.command == "list-users":
            from app.models.auth_models import UserAccount
            for user in db.query(UserAccount).order_by(UserAccount.username).all():
                out(f"{user.username}\t{user.role}\t{'active' if user.is_active else 'disabled'}")
            return 0
        err(f"Unknown command {args.command!r}.")
        return 2
    except ValueError as problem:
        err(str(problem))
        return 2
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())

"""The account CLI (python -m app.cli.accounts). Passwords come from getpass; the tests inject a reader instead of a terminal.
They run against the throw-away database conftest.py sets up, never socmind.db."""
import getpass
import inspect

import pytest

from app.cli import accounts as cli
from app.db.session import SessionLocal
from app.models.auth_models import UserAccount
from app.services import passwords as pw

PASSWORD = "cli passphrase that is long"


def answers(*values):
    """A stand-in for getpass: returns the given answers in order."""
    queue = list(values)

    def read(prompt):
        return queue.pop(0)
    return read


def run(args, *values):
    out, err = [], []
    code = cli.main(args, read_password=answers(*values), out=out.append, err=err.append)
    return code, out, err


def user_row(username):
    db = SessionLocal()
    try:
        return db.query(UserAccount).filter(UserAccount.username == username).first()
    finally:
        db.close()


def test_the_password_is_read_with_getpass_by_default():
    assert inspect.signature(cli.main).parameters["read_password"].default is getpass.getpass


def test_create_user_reads_the_password_twice_and_stores_only_a_hash():
    code, out, err = run(["create-user", "--username", "cli.ana", "--role", "analyst"], PASSWORD, PASSWORD)
    assert code == 0 and err == []
    assert out == ["Created the analyst account 'cli.ana'."]
    row = user_row("cli.ana")
    assert row is not None and row.role == "analyst" and row.is_active
    assert row.password_hash.startswith("scrypt$") and pw.verify_password(PASSWORD, row.password_hash)
    assert PASSWORD not in " ".join(out + err) and PASSWORD not in row.password_hash


def test_mismatched_passwords_create_nothing():
    code, out, err = run(["create-user", "--username", "cli.mismatch", "--role", "viewer"], PASSWORD, PASSWORD + "x")
    assert code == 2 and "do not match" in err[0]
    assert user_row("cli.mismatch") is None


def test_a_weak_password_is_refused_with_the_policy_message():
    code, _, err = run(["create-user", "--username", "cli.weak", "--role", "viewer"], "short", "short")
    assert code == 2 and "at least 12" in err[0]
    assert user_row("cli.weak") is None


def test_an_unknown_role_is_refused_by_the_parser():
    with pytest.raises(SystemExit) as exit_info:
        run(["create-user", "--username", "cli.root", "--role", "root"], PASSWORD, PASSWORD)
    assert exit_info.value.code == 2


def test_there_is_no_way_to_pass_the_password_on_the_command_line():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["create-user", "--username", "x", "--role", "viewer", "--password", PASSWORD])


def test_list_users_shows_names_roles_and_state_but_no_password_data():
    run(["create-user", "--username", "cli.listed", "--role", "approver"], PASSWORD, PASSWORD)
    code, out, _ = run(["list-users"])
    assert code == 0
    listed = [line for line in out if line.startswith("cli.listed")]
    assert listed == ["cli.listed\tapprover\tactive"]
    assert not any("scrypt" in line or PASSWORD in line for line in out)


def test_an_account_can_be_disabled_and_enabled_again():
    run(["create-user", "--username", "cli.toggle", "--role", "viewer"], PASSWORD, PASSWORD)
    assert run(["disable-user", "--username", "cli.toggle"])[0] == 0
    assert user_row("cli.toggle").is_active is False
    assert run(["enable-user", "--username", "cli.toggle"])[0] == 0
    assert user_row("cli.toggle").is_active is True


def test_disabling_an_unknown_account_is_a_clear_error():
    code, _, err = run(["disable-user", "--username", "cli.nobody-here"])
    assert code == 2 and "No account" in err[0]


def test_a_command_is_required():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args([])


def test_a_duplicate_username_is_refused_in_any_letter_case():
    run(["create-user", "--username", "cli.dupe", "--role", "viewer"], PASSWORD, PASSWORD)
    code, _, err = run(["create-user", "--username", "CLI.DUPE", "--role", "analyst"], PASSWORD, PASSWORD)
    assert code == 2 and "already exists" in err[0]
    assert user_row("cli.dupe").role == "viewer", "the first account is unchanged"


@pytest.mark.parametrize("bad_name", ["a", "has space", "semi;colon", "<script>", "x" * 70])
def test_invalid_usernames_are_refused_with_a_plain_message(bad_name):
    code, _, err = run(["create-user", "--username", bad_name, "--role", "viewer"], PASSWORD, PASSWORD)
    assert code == 2 and "username" in err[0].lower()


def test_an_empty_password_is_refused():
    code, _, err = run(["create-user", "--username", "cli.empty", "--role", "viewer"], "", "")
    assert code == 2 and "at least 12" in err[0]
    assert user_row("cli.empty") is None

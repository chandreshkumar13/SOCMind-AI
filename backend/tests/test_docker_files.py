"""Static checks on the container files (C13). Docker is NOT available in the environment these tests were written in, so the
images were never built here. These tests only check the files: no secrets or databases copied in, a non-root user, and
bounded dependency versions. They do not prove that an image builds or runs."""
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
BS = chr(92)  # one backslash. Built with chr() so that no escaping layer can turn it into two characters or a newline.


def _lines(path: Path):
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]


def _backend_text():
    return (BACKEND / "Dockerfile").read_text(encoding="utf-8")


def test_the_backend_image_runs_as_a_non_root_user_and_has_a_health_check():
    text = (BACKEND / "Dockerfile").read_text(encoding="utf-8")
    users = [line.split(None, 1)[1].strip() for line in text.splitlines() if line.strip().startswith("USER ")]
    assert users and users[-1] not in ("root", "0")
    assert "HEALTHCHECK" in text
    assert "--reload" not in text                              # development reloading does not belong in the image


def test_the_backend_image_copies_only_the_application_not_the_whole_directory():
    text = (BACKEND / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY . /app" not in text
    assert "COPY app " in text


def test_the_backend_build_context_excludes_secrets_databases_and_tests():
    patterns = _lines(BACKEND / ".dockerignore")
    for required in (".env", "*.db", "tests/", "__pycache__/"):
        assert required in patterns, required
    assert any(p.startswith("*.bak") or p.startswith("*.patch") for p in patterns)


def test_the_frontend_build_context_excludes_local_dependencies_and_secrets():
    patterns = _lines(ROOT / "frontend" / ".dockerignore")
    for required in ("node_modules", "dist", ".env*"):
        assert required in patterns, required


def test_the_frontend_image_installs_from_the_lockfile_and_runs_as_node():
    text = (ROOT / "frontend" / "Dockerfile").read_text(encoding="utf-8")
    assert "npm ci" in text
    assert "USER node" in text


def test_the_backend_image_declares_production_so_it_refuses_demo_auth():
    text = (BACKEND / "Dockerfile").read_text(encoding="utf-8")
    assert "ENVIRONMENT=production" in text


def test_the_frontend_base_image_is_a_supported_node_release_not_end_of_life():
    import re
    text = (ROOT / "frontend" / "Dockerfile").read_text(encoding="utf-8")
    match = re.search(r"^FROM node:(\d+)", text, re.MULTILINE)
    assert match, "no Node base image found"
    assert int(match.group(1)) >= 22, f"node:{match.group(1)} is end-of-life or not an LTS line"


def test_every_backend_dependency_has_an_upper_bound_so_a_major_upgrade_cannot_arrive_unnoticed():
    for line in _lines(BACKEND / "requirements.txt"):
        assert "<" in line, f"no upper bound: {line}"


def _steps(text):
    """The Dockerfile instructions, in order, as (keyword, rest) pairs, ignoring comments and blank lines."""
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            keyword, _, rest = stripped.partition(" ")
            out.append((keyword.upper(), rest))
    return out


def _logical_instructions(text):
    """Dockerfile instructions as Docker reads them: a physical line ending in a backslash continues on the next line.

    Returns (first_line_number, KEYWORD, arguments) for each instruction. Comment and blank lines are skipped. A continuation
    with no following line is an error, as it is for Docker."""
    out, buf, start = [], [], None
    for number, raw in enumerate(text.split("\n"), 1):
        stripped = raw.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if stripped.startswith("#"):
            continue                                   # Docker ignores comment lines inside a continued instruction
        if not buf:
            start = number
        buf.append(raw.rstrip())
        if buf[-1].endswith(BS):
            buf[-1] = buf[-1][:-1]
            continue
        joined = " ".join(part.strip() for part in buf).strip()
        keyword, _, args = joined.partition(" ")
        out.append((start, keyword.upper(), args.strip()))
        buf = []
    assert not buf, "the Dockerfile ends with a line continuation that has no next line"
    return out


def _literal_escape_problems(text):
    """A backslash followed by the letter n is two characters on the page, not a line break. Found in an instruction, Docker
    does not treat it as a continuation."""
    problems = []
    for number, raw in enumerate(text.split("\n"), 1):
        if raw.strip().startswith("#"):
            continue
        if BS + "n" in raw:
            problems.append(f"line {number}: literal backslash-n instead of a line continuation")
    return problems


def _run_problems(text):
    """Shell structure of every RUN instruction: no empty command between && operators, and every path given to chown or mkdir
    is absolute. A stray word left behind by a broken continuation (such as a lone 'n') is not an absolute path."""
    problems = []
    for number, keyword, args in _logical_instructions(text):
        if keyword != "RUN":
            continue
        for segment in (part.strip() for part in args.split("&&")):
            if not segment:
                problems.append(f"line {number}: empty command between && operators")
                continue
            words = segment.split()
            if words[0] == "chown":
                if len(words) < 3 or ":" not in words[1]:
                    problems.append(f"line {number}: chown needs an owner:group and at least one path, got {segment!r}")
                for path in words[2:]:
                    if not path.startswith("/"):
                        problems.append(f"line {number}: chown argument {path!r} is not an absolute path")
            if words[0] == "mkdir":
                for path in (w for w in words[1:] if not w.startswith("-")):
                    if not path.startswith("/"):
                        problems.append(f"line {number}: mkdir argument {path!r} is not an absolute path")
    return problems


def test_the_backend_dockerfile_contains_no_literal_backslash_n():
    assert _literal_escape_problems(_backend_text()) == []


def test_the_backend_run_instructions_have_valid_shell_structure():
    assert _run_problems(_backend_text()) == []


def test_the_backend_creates_the_sqlite_directory_as_its_non_root_user_in_order():
    runs = [args for _, keyword, args in _logical_instructions(_backend_text()) if keyword == "RUN"]
    owner_run = next(args for args in runs if "useradd" in args)
    segments = [part.strip() for part in owner_run.split("&&")]
    assert segments == ["useradd --create-home --uid 10001 socmind", "chown socmind:socmind /app",
                        "mkdir -p /app/data", "chown socmind:socmind /app/data"]


def test_the_checker_rejects_the_previously_broken_line():
    broken = ("RUN useradd --create-home --uid 10001 socmind && chown socmind:socmind /app " + BS + "n"
              "    && mkdir -p /app/data && chown socmind:socmind /app/data\n")
    assert _literal_escape_problems(broken), "the literal backslash-n must be reported"
    assert _run_problems(broken), "the stray n must be reported as a non-absolute chown path"


def test_the_checker_accepts_a_correct_continuation():
    fixed = ("RUN useradd --create-home --uid 10001 socmind && chown socmind:socmind /app " + BS + "\n"
             "    && mkdir -p /app/data && chown socmind:socmind /app/data\n")
    assert _literal_escape_problems(fixed) == []
    assert _run_problems(fixed) == []


def test_the_frontend_makes_the_app_directory_node_owned_before_it_switches_user():
    steps = _steps((ROOT / "frontend" / "Dockerfile").read_text(encoding="utf-8"))
    chown = [i for i, (k, rest) in enumerate(steps) if k == "RUN" and rest.startswith("chown node:node /app")]
    user = [i for i, (k, rest) in enumerate(steps) if k == "USER" and rest == "node"]
    install = [i for i, (k, rest) in enumerate(steps) if k == "RUN" and rest == "npm ci"]
    assert chown and user and install, "the chown, USER node and npm ci steps must all be present"
    assert chown[0] < user[0] < install[0], "npm ci and the Vite cache must run as node, in a directory node owns"
    assert not any(k == "USER" and rest.lower() in ("root", "0") for k, rest in steps)


def _compose():
    return (ROOT / "docker-compose.yml").read_text(encoding="utf-8")


def test_compose_is_marked_as_local_development_and_demo_only():
    assert "LOCAL DEVELOPMENT AND DEMO ONLY" in _compose()


def test_compose_publishes_ports_on_localhost_only():
    import re
    text = _compose()
    assert '"127.0.0.1:8000:8000"' in text and '"127.0.0.1:5173:5173"' in text
    assert not re.search(r'-\s+"(?!127\.0\.0\.1:)\d+:\d+"', text), "a port is published on all interfaces"


def test_compose_never_hard_codes_a_production_or_demo_environment():
    text = _compose()
    assert "- ENVIRONMENT=${SOCMIND_ENVIRONMENT:-development}" in text    # the image's production default is an explicit choice
    assert "- AUTH_MODE=${AUTH_MODE:-disabled}" in text                   # demo mode only as the explicit development default
    assert "- ENVIRONMENT=production" not in text


def test_compose_does_not_mount_source_code_over_the_image():
    assert "./backend:/app" not in _compose()


def test_compose_keeps_the_sqlite_database_in_a_named_volume_inside_the_data_directory():
    import re
    text = _compose()
    assert "DATABASE_URL=sqlite:////app/data/socmind.db" in text
    assert "- socmind-db:/app/data" in text
    assert re.search(r"^volumes:\n(?:[ ]*#[^\n]*\n)*[ ]+socmind-db:", text, re.MULTILINE)


def test_compose_mounts_the_sample_data_read_only():
    assert "./data:/data:ro" in _compose()

"""Process-model checks (final review, item 5): the worker count is read from WEB_CONCURRENCY and a warning is produced when
more than one worker process would make the per-process locks, caches and quotas unshared."""
from app.core.runtime import process_model_note, worker_processes


def test_the_worker_count_defaults_to_one_and_ignores_unreadable_values():
    assert worker_processes({}) == 1
    assert worker_processes({"WEB_CONCURRENCY": "0"}) == 1
    assert worker_processes({"WEB_CONCURRENCY": "not-a-number"}) == 1
    assert worker_processes({"WEB_CONCURRENCY": ""}) == 1


def test_the_worker_count_is_read_from_web_concurrency():
    assert worker_processes({"WEB_CONCURRENCY": "4"}) == 4
    assert worker_processes({"WEB_CONCURRENCY": " 2 "}) == 2


def test_one_process_produces_no_warning():
    assert process_model_note(1, live_provider=True) is None
    assert process_model_note(1, live_provider=False) is None


def test_several_processes_produce_a_warning_that_names_the_shared_state():
    note = process_model_note(4, live_provider=False)
    assert "4 worker processes" in note and "run lock" in note and "quota" in note
    assert "times the configured request budget" not in note


def test_live_lookups_with_several_processes_say_the_budget_can_multiply():
    assert "up to 4 times the configured request budget" in process_model_note(4, live_provider=True)

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


def test_seed_survives_a_concurrent_duplicate_insert(iso_client, monkeypatch):
    real_commit = Session.commit
    calls = {"n": 0}

    def flaky_commit(self):
        calls["n"] += 1
        if calls["n"] == 1:
            raise IntegrityError("INSERT", {}, Exception("UNIQUE constraint failed: alerts.id"))
        return real_commit(self)

    monkeypatch.setattr(Session, "commit", flaky_commit)
    res = iso_client.post("/api/v1/alerts/seed")
    assert res.status_code == 200 and res.json()["status"] == "success" and res.json()["inserted"] == 0

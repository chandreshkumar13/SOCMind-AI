"""Shared fakes for the VirusTotal tests: a fake clock, a fake VirusTotal server and a response builder."""
import httpx

KEY = "vt-test-KEY-do-not-leak-0123456789"


class Clock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def payload(malicious=0, suspicious=0, harmless=0, undetected=0, engines=(), date=1_700_000_000):
    results = {name: {"category": "malicious", "engine_name": name, "result": "bad"} for name in engines}
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": malicious, "suspicious": suspicious, "harmless": harmless,
                                                             "undetected": undetected, "timeout": 0},
                                    "last_analysis_results": results, "last_analysis_date": date, "reputation": 0}}}


class Server:
    """A fake VirusTotal: records every request and answers with `respond(request)`."""

    def __init__(self, respond=None):
        self.requests = []
        self.respond = respond or (lambda request: httpx.Response(200, json=payload(harmless=60, undetected=10)))

    def __call__(self, request):
        self.requests.append(request)
        return self.respond(request)

    @property
    def paths(self):
        return [r.url.path for r in self.requests]


def flags_bad_ip(request):
    """Benign for everything except 185.220.101.5, which 12 engines call malicious."""
    if request.url.path.endswith("/185.220.101.5"):
        return httpx.Response(200, json=payload(malicious=12, harmless=50, undetected=8, engines=["EngineA", "EngineB"]))
    return httpx.Response(200, json=payload(harmless=60, undetected=10))

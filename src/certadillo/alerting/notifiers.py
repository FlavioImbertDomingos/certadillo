"""Alert delivery channels. Each notifier gets the same Alert objects."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

import httpx

from certadillo.observability.metrics import NOTIFICATIONS

log = logging.getLogger("certadillo.alerting")


@dataclass
class Alert:
    fingerprint: str
    rule: str
    severity: str  # critical | warning | info
    summary: str
    labels: dict = field(default_factory=dict)
    status: str = "firing"  # firing | resolved
    runbook: str = ""


class Notifier:
    name = "base"

    def send(self, alerts: list[Alert]) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class LogNotifier(Notifier):
    name = "log"

    def send(self, alerts):
        for a in alerts:
            log.warning("alert", extra={"alert": {"rule": a.rule, "severity": a.severity, "status": a.status,
                                                  "summary": a.summary, **a.labels}})


class WebhookNotifier(Notifier):
    """Alertmanager-compatible webhook payload, so existing receivers work."""

    name = "webhook"

    def __init__(self, url: str, client: httpx.Client | None = None):
        self.url = url
        self.http = client or httpx.Client(timeout=10)

    def send(self, alerts):
        payload = {
            "version": "4",
            "receiver": "certadillo",
            "status": "firing" if any(a.status == "firing" for a in alerts) else "resolved",
            "alerts": [
                {
                    "status": a.status,
                    "labels": {"alertname": a.rule, "severity": a.severity, **{k: str(v) for k, v in a.labels.items()}},
                    "annotations": {"summary": a.summary, "runbook_url": a.runbook},
                    "fingerprint": a.fingerprint,
                }
                for a in alerts
            ],
        }
        self.http.post(self.url, json=payload).raise_for_status()


class SlackNotifier(Notifier):
    name = "slack"
    ICON = {"critical": ":rotating_light:", "warning": ":warning:", "info": ":information_source:"}

    def __init__(self, url: str, client: httpx.Client | None = None):
        self.url = url
        self.http = client or httpx.Client(timeout=10)

    def send(self, alerts):
        lines = []
        for a in alerts:
            state = "RESOLVED" if a.status == "resolved" else a.severity.upper()
            lines.append(f"{self.ICON.get(a.severity, '')} *[{state}] {a.rule}*: {a.summary}")
            if a.runbook:
                lines.append(f"    runbook: {a.runbook}")
        self.http.post(self.url, json={"text": "Dilly spotted something:\n" + "\n".join(lines)}).raise_for_status()


class JiraNotifier(Notifier):
    """Opens one Jira issue per new critical alert (change/problem tracking)."""

    name = "jira"

    def __init__(self, base_url: str, user: str, token: str, project: str, client: httpx.Client | None = None):
        self.base = base_url.rstrip("/")
        self.auth = (user, token)
        self.project = project
        self.http = client or httpx.Client(timeout=15)

    def send(self, alerts):
        for a in alerts:
            if a.status != "firing" or a.severity != "critical":
                continue
            body = {
                "fields": {
                    "project": {"key": self.project},
                    "issuetype": {"name": "Task"},
                    "summary": f"[certadillo] {a.rule}: {a.summary}"[:250],
                    "description": "\n".join(f"{k}: {v}" for k, v in a.labels.items())
                    + f"\n\nRunbook: {a.runbook}\nFingerprint: {a.fingerprint}",
                    "labels": ["certadillo", a.rule],
                }
            }
            self.http.post(f"{self.base}/rest/api/2/issue", json=body, auth=self.auth).raise_for_status()


class ServiceNowNotifier(Notifier):
    """Creates ServiceNow incidents; correlation_id keeps them de-duplicated."""

    name = "servicenow"

    def __init__(self, instance_url: str, user: str, password: str, assignment_group: str,
                 client: httpx.Client | None = None):
        self.base = instance_url.rstrip("/")
        self.auth = (user, password)
        self.group = assignment_group
        self.http = client or httpx.Client(timeout=15)

    def send(self, alerts):
        for a in alerts:
            if a.status != "firing" or a.severity != "critical":
                continue
            body = {
                "short_description": f"[certadillo] {a.summary}"[:160],
                "description": "\n".join(f"{k}: {v}" for k, v in a.labels.items()) + f"\nRunbook: {a.runbook}",
                "urgency": "1",
                "impact": "2",
                "assignment_group": self.group,
                "correlation_id": a.fingerprint,
                "category": "Security",
            }
            self.http.post(f"{self.base}/api/now/table/incident", json=body, auth=self.auth,
                           headers={"Accept": "application/json"}).raise_for_status()


def deliver(notifier: Notifier, alerts: list[Alert]) -> bool:
    if not alerts:
        return True
    try:
        notifier.send(alerts)
        NOTIFICATIONS.labels(channel=notifier.name, result="ok").inc()
        return True
    except Exception as e:  # noqa: BLE001 - never let one channel break the loop
        NOTIFICATIONS.labels(channel=notifier.name, result="error").inc()
        log.error("notification failed", extra={"channel": notifier.name, "error": str(e)})
        return False


def build_global_notifiers(settings) -> list[Notifier]:
    out: list[Notifier] = [LogNotifier()]
    out += [WebhookNotifier(u) for u in settings.webhook_urls]
    out += [SlackNotifier(u) for u in settings.slack_webhook_urls]
    if settings.jira_url and settings.jira_user and settings.jira_token:
        out.append(JiraNotifier(settings.jira_url, settings.jira_user, settings.jira_token, settings.jira_project))
    if settings.snow_url and settings.snow_user and settings.snow_password:
        out.append(ServiceNowNotifier(settings.snow_url, settings.snow_user, settings.snow_password,
                                      settings.snow_assignment_group))
    return out

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
import base64
from urllib.parse import quote, unquote


def b64e(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


def b64d(value: str) -> str | None:
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode()).decode()
    except Exception:
        return None


def hexe(value: str) -> str:
    return value.encode().hex()


def double_urlencode(value: str) -> str:
    return quote(quote(value, safe=""), safe="")


def wrap_fbclid(value: str) -> str:
    return f"fb.1.{double_urlencode(b64e(value))}.sig"


def wrap_gclid(value: str) -> str:
    return f"gcl::{hexe(value)}::ad"


def wrap_ttclid(value: str) -> str:
    return f"tt.{quote(b64e(value), safe='')}~end"


def wrap_msclkid(value: str) -> str:
    return f"ms.{double_urlencode(b64e(value))}.trail"


def decode_fbclid(value: str) -> str:
    parts = value.split(".")
    if len(parts) < 4:
        return "decode-error"
    return b64d(unquote(parts[2])) or "decode-error"


def decode_gclid(value: str) -> str:
    parts = value.split("::")
    if len(parts) < 3:
        return "decode-error"
    try:
        return bytes.fromhex(parts[1]).decode()
    except Exception:
        return "decode-error"


def decode_ttclid(value: str) -> str:
    if not value.startswith("tt.") or "~" not in value:
        return "decode-error"
    middle = value[3:value.index("~")]
    return b64d(unquote(middle)) or "decode-error"


def decode_msclkid(value: str) -> str:
    parts = value.split(".")
    if len(parts) < 3:
        return "decode-error"
    return b64d(unquote(parts[1])) or "decode-error"


@dataclass(frozen=True)
class ScenarioSpec:
    label: str
    site_path: str
    site_param: str
    sample_value: str
    tracker_path: str
    tracker_param: str
    cookie_name: str
    redirect_builder: Callable[[str], str]
    cookie_builder: Callable[[str], str]

    def site_url(self) -> str:
        return f"{self.site_path}?{self.site_param}={quote(self.sample_value, safe='')}"

    def redirected_url(self, value: str | None = None) -> str:
        actual = value or self.sample_value
        return f"{self.tracker_path}?{self.tracker_param}={quote(self.redirect_builder(actual), safe='')}"


AD_SCENARIOS = [
    ScenarioSpec(
        label="Meta-like click id",
        site_path="/site/meta",
        site_param="fbclid",
        sample_value="user-meta-234",
        tracker_path="/tracker/meta",
        tracker_param="event_id",
        cookie_name="_fbc",
        redirect_builder=wrap_fbclid,
        cookie_builder=decode_fbclid,
    ),
    ScenarioSpec(
        label="Search ad id",
        site_path="/site/search",
        site_param="gclid",
        sample_value="user-search-345",
        tracker_path="/tracker/search",
        tracker_param="adid",
        cookie_name="_gcl_au",
        redirect_builder=wrap_gclid,
        cookie_builder=decode_gclid,
    ),
    ScenarioSpec(
        label="Video click id",
        site_path="/site/video",
        site_param="ttclid",
        sample_value="user-video-456",
        tracker_path="/tracker/video",
        tracker_param="click_id",
        cookie_name="_ttp",
        redirect_builder=wrap_ttclid,
        cookie_builder=decode_ttclid,
    ),
    ScenarioSpec(
        label="Commerce session id",
        site_path="/site/commerce",
        site_param="msclkid",
        sample_value="user-commerce-567",
        tracker_path="/tracker/commerce",
        tracker_param="aid",
        cookie_name="ubid-main",
        redirect_builder=wrap_msclkid,
        cookie_builder=decode_msclkid,
    ),
]

AD_SCENARIOS_BY_SITE_PATH = {scenario.site_path: scenario for scenario in AD_SCENARIOS}
AD_SCENARIOS_BY_TRACKER_PATH = {scenario.tracker_path: scenario for scenario in AD_SCENARIOS}


def ad_scenario_urls() -> list[str]:
    return [scenario.site_url() for scenario in AD_SCENARIOS]


def ad_root_links_html() -> str:
    return "\n".join(
        f"              <li><a href='{scenario.site_url()}'>{scenario.site_url()}</a></li>"
        for scenario in AD_SCENARIOS
    )
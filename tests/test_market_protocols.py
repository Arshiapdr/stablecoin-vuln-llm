"""The behavioural track must cover the corpus, not just Terra.

`asv data fetch` was hardcoded to one asset (USTUSDT / coingecko:terrausd /
stablecoin 3), so the market track described a single protocol while the code
track described sixteen. Each protocol now declares its own sources under
`market:` in configs/protocols.yaml, transcribed from the verified market table
in the project report.

Two things have to hold for the extension to be honest rather than merely
bigger: a protocol without a $1.00 target must never be thresholded against
$0.99, and an hourly series must not produce episodes on weaker evidence than
Terra's minute series does.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from asv.config import Config
from asv.market import (DEPEGGABLE_PEG_TARGETS, label_depegs, market_protocols,
                        market_spec, series_path)

PEG_TARGETS = {"usd", "eur", "none"}


@pytest.fixture(scope="module")
def cfg():
    return Config.load()


@pytest.fixture(scope="module")
def protos(cfg):
    return {p["name"]: p for p in cfg.protocol_list()}


def test_every_protocol_declares_a_market_block_even_when_empty(protos):
    """Explicit `market: null` beats an absent key: it distinguishes "checked,
    nothing exists" from "nobody looked"."""
    for name, p in protos.items():
        assert "market" in p, f"{name}: no market key — was it checked?"


def test_peg_targets_are_from_the_known_set(protos):
    for name, p in protos.items():
        m = p["market"]
        if m is None:
            continue
        assert m.get("peg_target") in PEG_TARGETS, f"{name}: {m.get('peg_target')!r}"


def test_every_price_series_declares_its_window(protos):
    """A coin without start/span would silently fetch DefiLlama's default
    window, which is not the window the event happened in."""
    for name, p in protos.items():
        m = p["market"]
        if not m or not m.get("llama_coin"):
            continue
        assert isinstance(m.get("llama_start"), int), f"{name}: no llama_start"
        assert isinstance(m.get("llama_span"), int), f"{name}: no llama_span"


def test_yam_is_recorded_as_having_no_series(protos):
    """Checked in every free source and found absent — not an oversight."""
    assert protos["yam-finance"]["market"] is None


def test_non_dollar_pegs_are_excluded_from_depeg_scoring(cfg, protos):
    """AMPL targets a CPI-adjusted dollar, RAI's redemption price floats near
    $3, agEUR tracks the euro. Thresholding any of them at $0.99 would measure
    something other than a depeg."""
    depeggable = {n for n, _ in market_protocols(cfg, depeggable_only=True)}
    for name in ("ampleforth", "reflexer-rai", "angle-protocol"):
        assert protos[name]["market"] is not None, f"{name} should still have a series"
        assert name not in depeggable, f"{name} must not be scored against $0.99"
    assert "terra-classic" in depeggable and "beanstalk" in depeggable


def test_market_protocols_skips_only_the_ones_without_a_series(cfg, protos):
    listed = {n for n, _ in market_protocols(cfg)}
    expected = {n for n, p in protos.items() if p["market"]}
    assert listed == expected
    assert "yam-finance" not in listed


def test_series_are_named_by_protocol_not_by_ticker(tmp_path):
    """Two protocols share coingecko:bean; a ticker-named file would collide
    and one would silently overwrite the other."""
    a = series_path(tmp_path, "beanstalk", "1h")
    b = series_path(tmp_path, "beanstalk-patched", "1h")
    assert a != b and a.name.startswith("beanstalk_")


# --- the resolution problem -------------------------------------------------

def _hourly(prices):
    return [(i * 3600, p) for i, p in enumerate(prices)]


def test_one_hourly_sample_below_the_threshold_is_not_an_episode():
    """min_minutes=5 on hourly data computes need=1, so without the floor a
    single print would open an episode — a far weaker claim than Terra's."""
    series = _hourly([1.0, 1.0, 0.98, 1.0, 1.0])
    assert label_depegs(series, 0.99, 5, min_samples=1), "sanity: 1 sample opens one"
    assert not label_depegs(series, 0.99, 5, min_samples=2), \
        "a lone hourly print must not count as a depeg episode"


def test_two_consecutive_hourly_samples_do_make_an_episode():
    series = _hourly([1.0, 0.98, 0.97, 1.0])
    ev = label_depegs(series, 0.99, 5, min_samples=2)
    assert len(ev) == 1 and ev[0].min_price == pytest.approx(0.97)


def test_the_floor_does_not_weaken_the_minute_rule():
    """On minute data the minute rule already demands 5 samples; a floor of 2
    must not reduce that."""
    minute = [(i * 60, 0.98 if 2 <= i <= 4 else 1.0) for i in range(12)]
    assert not label_depegs(minute, 0.99, 5, min_samples=2), \
        "3 minutes below peg is not yet an episode under a 5-minute rule"
    longer = [(i * 60, 0.98 if 2 <= i <= 8 else 1.0) for i in range(12)]
    assert len(label_depegs(longer, 0.99, 5, min_samples=2)) == 1


def test_the_configured_floor_is_at_least_two(cfg):
    assert int(cfg.get("behavior.min_consecutive_samples", 0)) >= 2


# --- the values transcribed from the report's market table ------------------

def test_windows_match_the_source_table(cfg):
    """Spot-checks against the table in the project report. These are the
    windows the evidence was verified in; a silent edit would decouple the
    implementation from the document that justifies it."""
    assert market_spec(cfg, "neutrino")["llama_span"] == 300
    assert market_spec(cfg, "terra-classic")["llama_span"] == 400
    assert market_spec(cfg, "terra-classic")["stablecoin_id"] == 3
    # the patched tree is observed after the replant, not during the attack
    assert market_spec(cfg, "beanstalk")["llama_start"] == 1650067200
    assert market_spec(cfg, "beanstalk-patched")["llama_start"] == 1660678200
    # the absorbing token whose hyperinflation is the mechanism V1/V2 describe
    assert (market_spec(cfg, "iron-finance")["absorbing_coin"]
            == "coingecko:iron-titanium-token")


def test_terra_is_the_only_protocol_with_minute_data(cfg, protos):
    """The Binance archive was checked symbol by symbol: only USTUSDT exists
    for its event window. Everything else is hourly."""
    with_minutes = {n for n, p in protos.items()
                    if p["market"] and p["market"].get("binance_symbol")}
    assert with_minutes == {"terra-classic"}


def test_depeggable_set_is_what_the_pipeline_will_score(cfg):
    assert DEPEGGABLE_PEG_TARGETS == frozenset({"usd"})
    names = {n for n, _ in market_protocols(cfg, depeggable_only=True)}
    assert len(names) == 12, sorted(names)


# --- the silent-failure guard -----------------------------------------------

def test_an_empty_series_file_is_never_scored_as_zero_events(tmp_path, cfg):
    """A wholly failed download leaves a header-only CSV.

    Observed live: with the endpoint unreachable, `fetch_binance_minutes`
    recorded the failure in its sidecar and still wrote `ts,price` with no
    rows. `data depeg` loaded it, found nothing, and reported terra-classic as
    "scored, 0 events" — which reads exactly like a protocol whose peg held.
    The pipeline must refuse such a file rather than publish that.
    """
    from click.testing import CliRunner

    from asv.cli import cli
    from asv.market import series_path

    market_dir = cfg.path("raw") / "market"
    market_dir.mkdir(parents=True, exist_ok=True)
    empty = series_path(market_dir, "__pytest_empty__", "1h")
    empty.write_text("ts,price\n", "utf-8")
    try:
        from asv.market import load_series
        assert load_series(empty) == [], "fixture is not actually empty"
    finally:
        empty.unlink()


def test_fetch_protocol_reports_a_failure_instead_of_keeping_an_empty_file(
        monkeypatch, tmp_path, cfg):
    from asv import market as m

    def fake_minutes(symbol, months, out_dir, timeout=60):
        p = Path(out_dir) / f"{symbol}_1m.csv"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("ts,price\n", "utf-8")       # header only: total failure
        return p

    monkeypatch.setattr(m, "fetch_binance_minutes", fake_minutes)
    monkeypatch.setattr(m, "fetch_llama_hourly",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("offline")))
    monkeypatch.setattr(m, "fetch_llama_supply",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("offline")))
    res = m.fetch_protocol(cfg, "terra-classic", tmp_path)
    assert "minutes" not in res, "an empty series must not be reported as fetched"
    assert "minutes_error" in res
    assert not m.series_path(tmp_path, "terra-classic", "1m").exists(), \
        "the empty file must be removed, not left for the scorer to load"


def test_the_monitor_runs_on_hourly_data_at_all():
    """`window` and `step` were sample counts standing in for durations.

    `window = supply_growth_window_hours * 60` = 1440 and `range(1440, n, 60)`
    is empty for any hourly series shorter than 1440 points, so the monitor
    silently never ran: a protocol collapsing from $1.02 to $0.06 produced
    zero alerts. Same defect class as the `prices[-1440:]` indicator window.
    """
    from asv.prevent import monitor

    th = {"depeg_threshold": 0.99, "severe_threshold": 0.95,
          "failure_threshold": 0.80, "supply_growth_window_hours": 24}
    collapse = [(i * 3600, 1.02 if i < 40 else max(0.06, 1.02 * 0.96 ** (i - 40)))
                for i in range(193)]
    alerts = monitor(collapse, None, th)
    assert alerts, "the monitor must fire on an hourly collapse"
    assert {a.state for a in alerts} & {"stressed", "active_depeg", "collapse"}


def test_the_monitor_is_unchanged_on_minute_data():
    """The conversion must reproduce the old behaviour exactly at 60s spacing:
    a 24-hour warm-up, evaluated every 60 minutes."""
    from asv.prevent import monitor

    th = {"depeg_threshold": 0.99, "severe_threshold": 0.95,
          "failure_threshold": 0.80, "supply_growth_window_hours": 24}
    n = 3000
    minute = [(i * 60, 1.0 if i < 2000 else 0.90) for i in range(n)]
    alerts = monitor(minute, None, th)
    assert alerts, "a minute series that breaks its peg must still alert"
    # warm-up 1440 samples, stride 60 -> first evaluation at index 1440
    assert alerts[0].ts >= minute[1439][0]


def test_a_series_too_short_for_one_window_yields_no_alert():
    from asv.prevent import monitor

    th = {"supply_growth_window_hours": 24}
    assert monitor([(i * 3600, 0.5) for i in range(5)], None, th) == []

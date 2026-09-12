"""Stage 4 — behavioural track: price/supply data, depeg labels, indicators.

Covers report categories A1 (death spiral) and A2 (arbitrage manipulation) on
the data side, which cannot be seen in contract code.

Data sources (all free, verified 2026-08-25):
  * minute prices : data.binance.vision monthly kline ZIPs (no key)
  * hourly prices : coins.llama.fi/chart                  (no key)
  * daily supply  : stablecoins.llama.fi/stablecoincharts (no key)
"""
from __future__ import annotations

import csv
import io
import json
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import requests

BINANCE = "https://data.binance.vision/data/spot/monthly/klines/{sym}/1m/{sym}-1m-{ym}.zip"
LLAMA_CHART = "https://coins.llama.fi/chart/{coin}"
LLAMA_SUPPLY = "https://stablecoins.llama.fi/stablecoincharts/all"
LLAMA_LIST = "https://stablecoins.llama.fi/stablecoins"
LLAMA_HACKS = "https://api.llama.fi/hacks"


# --- fetching ---------------------------------------------------------------
def fetch_binance_minutes(symbol: str, months: list[str], out_dir: Path,
                          timeout: int = 60) -> Path:
    """Download monthly 1m kline ZIPs and write a single tidy CSV.

    months: e.g. ["2022-04", "2022-05"].

    A month that fails to download is recorded in `<symbol>_1m.missing.json`
    beside the CSV. Skipping it silently would leave a hole in the series that
    `label_depegs` cannot distinguish from real data — and a hole is exactly
    what makes two short episodes look like one long one.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    rows: list[tuple[int, float]] = []
    missing: list[str] = []
    for ym in months:
        url = BINANCE.format(sym=symbol, ym=ym)
        try:
            r = requests.get(url, timeout=timeout)
        except requests.RequestException as exc:
            missing.append(f"{ym}: {type(exc).__name__}")
            continue
        if r.status_code != 200:
            missing.append(f"{ym}: HTTP {r.status_code}")
            continue
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            for name in z.namelist():
                for line in z.read(name).decode().splitlines():
                    parts = line.split(",")
                    if len(parts) < 5:
                        continue
                    try:
                        ts = int(float(parts[0]))
                        close = float(parts[4])
                    except ValueError:
                        continue          # header row in newer dumps
                    if ts > 10 ** 13:     # microsecond timestamps
                        ts //= 1000
                    rows.append((ts // 1000, close))
    rows.sort()
    # de-duplicate on timestamp: overlapping dumps otherwise inflate sample counts
    deduped: list[tuple[int, float]] = []
    for r_ts, r_px in rows:
        if not deduped or deduped[-1][0] != r_ts:
            deduped.append((r_ts, r_px))
    path = out_dir / f"{symbol}_1m.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ts", "price"])
        w.writerows(deduped)
    (out_dir / f"{symbol}_1m.missing.json").write_text(
        json.dumps({"requested": months, "missing": missing,
                    "rows": len(deduped), "duplicates_dropped": len(rows) - len(deduped)},
                   indent=1), "utf-8")
    return path


def fetch_llama_hourly(coin: str, start_ts: int, span: int, out_dir: Path,
                       timeout: int = 60) -> Path:
    """Hourly price series from DefiLlama. `coin` e.g. 'coingecko:terrausd'."""
    out_dir.mkdir(parents=True, exist_ok=True)
    r = requests.get(LLAMA_CHART.format(coin=coin),
                     params={"start": start_ts, "span": span, "period": "1h",
                             "searchWidth": 600}, timeout=timeout)
    r.raise_for_status()
    body = r.json().get("coins", {})
    prices = next(iter(body.values()), {}).get("prices", []) if body else []
    path = out_dir / f"{coin.replace(':', '_')}_1h.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ts", "price"])
        for p in prices:
            w.writerow([int(p["timestamp"]), float(p["price"])])
    return path


def fetch_llama_supply(stablecoin_id: int, out_dir: Path, timeout: int = 60) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    r = requests.get(LLAMA_SUPPLY, params={"stablecoin": stablecoin_id}, timeout=timeout)
    r.raise_for_status()
    path = out_dir / f"supply_{stablecoin_id}.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ts", "circulating"])
        for row in r.json():
            circ = (row.get("totalCirculating") or {}).get("peggedUSD")
            if circ is not None:
                w.writerow([int(row["date"]), float(circ)])
    return path


def fetch_hacks(out_dir: Path, timeout: int = 60) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    r = requests.get(LLAMA_HACKS, timeout=timeout)
    r.raise_for_status()
    path = out_dir / "hacks.json"
    path.write_text(json.dumps(r.json(), indent=1), "utf-8")
    return path


def load_series(path: Path) -> list[tuple[int, float]]:
    out: list[tuple[int, float]] = []
    with Path(path).open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            k = "price" if "price" in row else "circulating"
            try:
                out.append((int(row["ts"]), float(row[k])))
            except (ValueError, KeyError):
                continue
    out.sort()
    return out


# --- depeg labelling --------------------------------------------------------
@dataclass
class DepegEvent:
    kind: str                 # depeg | severe | failure
    start_ts: int
    end_ts: int
    duration_min: int
    min_price: float
    start_iso: str = ""
    end_iso: str = ""

    def __post_init__(self):
        self.start_iso = datetime.fromtimestamp(self.start_ts, timezone.utc).isoformat()
        self.end_iso = datetime.fromtimestamp(self.end_ts, timezone.utc).isoformat()


def label_depegs(series: list[tuple[int, float]], threshold: float = 0.99,
                 min_minutes: int = 5, kind: str = "depeg",
                 step_seconds: int | None = None,
                 max_gap_steps: int = 3,
                 min_samples: int = 1) -> list[DepegEvent]:
    """Price below `threshold` for at least `min_minutes` of *contiguous* data.

    `step_seconds` defaults to the median sample spacing, so the same function
    works on minute and hourly data.

    `min_samples` is a FLOOR on the number of consecutive samples required,
    applied after the minute-based count. It exists because the two resolutions
    are not comparable without it: `need = ceil(min_minutes*60 / step_seconds)`
    gives 5 samples on minute data but **1** on hourly data, so a single hourly
    print below the threshold would open an episode. Terra's episodes would be
    five-times-confirmed while every hourly protocol's would rest on one point,
    and the same word "depeg" would mean two different evidentiary standards in
    one table. Default 1 preserves the original behaviour for direct callers;
    the pipeline passes `behavior.min_consecutive_samples`.

    A run is broken when the spacing between two consecutive samples exceeds
    `max_gap_steps * step_seconds`. Without this, a hole in the data (a month
    Binance never served, a DefiLlama outage) silently welds two separate
    episodes into one: six minutes below peg, a three-day gap, six more minutes
    below peg was reported as a single depeg lasting three days. Duration is
    derived from timestamps, so a merged run also corrupts `duration_min`.
    """
    if not series:
        return []
    if step_seconds is None:
        gaps = sorted(b[0] - a[0] for a, b in zip(series, series[1:])) or [60]
        step_seconds = max(1, gaps[len(gaps) // 2])
    need = max(1, (min_minutes * 60 + step_seconds - 1) // step_seconds,
               int(min_samples))
    max_gap = max(1, max_gap_steps) * step_seconds

    events: list[DepegEvent] = []
    run_start: int | None = None
    run_lo = 1e9
    count = 0
    prev_ts = series[0][0]

    def close_run(end_ts: int) -> None:
        nonlocal run_start, run_lo, count
        if run_start is not None and count >= need:
            events.append(DepegEvent(kind, run_start, end_ts,
                                     _minutes(run_start, end_ts, step_seconds),
                                     run_lo))
        run_start, count, run_lo = None, 0, 1e9

    for ts, price in series:
        if run_start is not None and ts - prev_ts > max_gap:
            close_run(prev_ts)          # data hole: the episode ends here
        if price < threshold:
            if run_start is None:
                run_start, run_lo, count = ts, price, 1
            else:
                count += 1
                run_lo = min(run_lo, price)
        else:
            close_run(prev_ts)
        prev_ts = ts
    close_run(prev_ts)
    return events


def _minutes(start_ts: int, end_ts: int, step_seconds: int) -> int:
    """Duration covered by the samples, inclusive of the last one."""
    return max(1, int((end_ts - start_ts + step_seconds) / 60))


# --- indicators -------------------------------------------------------------
@dataclass
class Indicators:
    peg_deviation: float          # |P - 1|
    min_price_window: float
    supply_growth_24h: float      # absorbing-token supply growth ratio
    backing_ratio: float          # absorbing mcap / stablecoin supply
    pool_imbalance: float         # max share of one side of the pool
    state: str = "normal"
    alerts: list[str] = None      # type: ignore[assignment]

    def __post_init__(self):
        if self.alerts is None:
            self.alerts = []


def compute_indicators(prices: list[tuple[int, float]],
                       absorbing_supply: list[tuple[int, float]] | None = None,
                       absorbing_mcap: float | None = None,
                       stable_supply: float | None = None,
                       pool_shares: list[float] | None = None,
                       cfg_thresholds: dict | None = None) -> Indicators:
    t = cfg_thresholds or {}
    depeg_th = float(t.get("depeg_threshold", 0.99))
    severe_th = float(t.get("severe_threshold", 0.95))
    fail_th = float(t.get("failure_threshold", 0.80))
    growth_alert = float(t.get("supply_growth_alert", 0.50))
    backing_alert = float(t.get("backing_ratio_alert", 1.5))
    pool_alert = float(t.get("pool_imbalance_alert", 0.70))

    last = prices[-1][1] if prices else 1.0
    # Window must be measured in TIME, not in samples. `prices[-1440:]` is 24h
    # only if the series is minutely; on hourly data it is 60 days, so `state`
    # would latch on the first depeg and never return to normal — which in turn
    # makes the monitor emit one alert and never another.
    win_min = int(t.get("indicator_window_minutes", 1440))
    if prices:
        cutoff_ts = prices[-1][0] - win_min * 60
        window = [p for ts, p in prices if ts >= cutoff_ts] or [prices[-1][1]]
    else:
        window = [1.0]
    lo = min(window)

    growth = float("nan")
    if absorbing_supply and len(absorbing_supply) > 1:
        cutoff = absorbing_supply[-1][0] - int(t.get("supply_growth_window_hours", 24)) * 3600
        past = [v for ts, v in absorbing_supply if ts <= cutoff]
        base = past[-1] if past else absorbing_supply[0][1]
        # `base or 1.0` would turn a zero baseline into a divide-by-one and
        # report the entire supply as "growth". A zero baseline is undefined.
        growth = ((absorbing_supply[-1][1] - base) / base) if base > 0 else float("nan")

    backing = (absorbing_mcap / stable_supply) if (absorbing_mcap and stable_supply) else float("nan")
    imbalance = max(pool_shares) if pool_shares else float("nan")

    alerts: list[str] = []
    if lo < fail_th:
        state = "collapse"
    elif lo < severe_th:
        state = "active_depeg"
    elif lo < depeg_th:
        state = "stressed"
    else:
        state = "normal"
    if lo < depeg_th:
        alerts.append(f"price touched {lo:.4f} (< {depeg_th})")
    if growth == growth and growth > growth_alert:   # NaN-safe
        alerts.append(f"absorbing supply +{growth:.1%} in window")
        state = "active_depeg" if state == "normal" else state
    if backing == backing and backing < backing_alert:
        alerts.append(f"backing ratio {backing:.2f} < {backing_alert}")
        state = "active_depeg" if state in ("normal", "stressed") else state
    if imbalance == imbalance and imbalance > pool_alert:
        alerts.append(f"pool imbalance {imbalance:.0%} > {pool_alert:.0%}")

    growth_out = growth if growth != growth else round(growth, 6)  # keep NaN as NaN
    return Indicators(round(abs(last - 1.0), 6), round(lo, 6), growth_out,
                      backing, imbalance, state, alerts)


# --- sensitivity ------------------------------------------------------------
def sensitivity(series: list[tuple[int, float]], grid: list[float],
                min_minutes: int = 5, min_samples: int = 1) -> dict[str, dict]:
    """Re-label the series at each threshold in `grid`.

    `min_samples` MUST be the same floor the headline events were labelled
    with. Sweeping with the default floor of 1 while the events themselves
    require 2 consecutive samples makes the sweep a sensitivity analysis of a
    DIFFERENT estimator: the row at the headline threshold then disagrees with
    the event list in the same file (Liquity: "0 events at 0.99" beside
    "0.99 -> 120 minutes"), which reads as a contradiction rather than as the
    two different rules it actually is.
    """
    out: dict[str, dict] = {}
    for th in grid:
        ev = label_depegs(series, threshold=th, min_minutes=min_minutes,
                          min_samples=min_samples)
        out[f"{th:g}"] = {
            "events": len(ev),
            "total_minutes": sum(e.duration_min for e in ev),
            "min_price": min((e.min_price for e in ev), default=None),
        }
    return out


def events_to_json(events: list[DepegEvent]) -> list[dict]:
    return [asdict(e) for e in events]


# --- per-protocol market series ---------------------------------------------
#
# Until now this module knew nothing about protocols: `asv data fetch` was
# hardcoded to a single asset (USTUSDT / coingecko:terrausd / stablecoin 3), so
# the behavioural track covered Terra alone while the code track covered 16
# protocols. The `market:` block in configs/protocols.yaml now carries, per
# protocol, exactly the sources verified in the project report's market table.

#: Protocols whose design target is not a fixed $1.00. Their price series are
#: still fetched — they are legitimate evidence — but they are never handed to
#: `label_depegs`, because deviation from $1.00 is not defined for them:
#:   none - AMPL (CPI-adjusted dollar, defended by rebasing balances)
#:          RAI  (floating redemption price, ~$3.02 in the window)
#:   eur  - agEUR (euro peg; a $0.99 threshold measures EUR/USD drift)
DEPEGGABLE_PEG_TARGETS = frozenset({"usd"})


def market_spec(cfg, name: str) -> dict | None:
    """The `market:` block for one protocol, or None when it has no series."""
    for p in cfg.protocol_list():
        if p["name"] == name:
            return p.get("market") or None
    return None


def market_protocols(cfg, depeggable_only: bool = False) -> list[tuple[str, dict]]:
    """(name, market) for every protocol that has a market series.

    With `depeggable_only`, drops the ones whose peg target is not USD, so a
    caller cannot accidentally threshold a euro-pegged or CPI-adjusted series
    against $0.99.
    """
    out = []
    for p in cfg.protocol_list():
        m = p.get("market")
        if not m:
            continue
        if depeggable_only and m.get("peg_target") not in DEPEGGABLE_PEG_TARGETS:
            continue
        out.append((p["name"], m))
    return out


def series_path(out_dir: Path, protocol: str, kind: str = "1h") -> Path:
    """Where one protocol's series lives. Named by PROTOCOL, not by ticker, so
    a file can always be traced back to the corpus entry that produced it."""
    return Path(out_dir) / f"{protocol}_{kind}.csv"


def fetch_protocol(cfg, name: str, out_dir: Path, timeout: int = 60) -> dict:
    """Fetch every series the `market:` block declares for one protocol.

    Each leg is attempted independently and its failure recorded, so one dead
    endpoint cannot abort a 16-protocol run.
    """
    spec = market_spec(cfg, name)
    out_dir = Path(out_dir)
    if not spec:
        return {"protocol": name, "skipped": "no market series declared"}
    res: dict = {"protocol": name, "peg_target": spec.get("peg_target")}

    if spec.get("binance_symbol") and spec.get("binance_months"):
        try:
            p = fetch_binance_minutes(spec["binance_symbol"],
                                      list(spec["binance_months"]), out_dir,
                                      timeout=timeout)
            dest = series_path(out_dir, name, "1m")
            p.replace(dest)          # Path.replace = move, overwriting
            # A download that failed entirely still leaves a header-only CSV,
            # because fetch_binance_minutes records the failure in its sidecar
            # and writes whatever it got. Keeping that file is worse than
            # keeping nothing: `data depeg` would load it, find no samples and
            # report "0 events" — indistinguishable from a protocol whose peg
            # held. Delete it and surface the failure instead.
            if len(load_series(dest)) == 0:
                dest.unlink()
                res["minutes_error"] = "no samples returned (see *_1m.missing.json)"
            else:
                res["minutes"] = str(dest)
                res["minute_samples"] = len(load_series(dest))
        except Exception as e:                              # noqa: BLE001
            res["minutes_error"] = f"{type(e).__name__}: {e}"

    if spec.get("llama_coin"):
        try:
            p = fetch_llama_hourly(spec["llama_coin"], int(spec["llama_start"]),
                                   int(spec.get("llama_span", 200)), out_dir,
                                   timeout=timeout)
            dest = series_path(out_dir, name, "1h")
            p.replace(dest)
            if len(load_series(dest)) == 0:
                dest.unlink()
                res["hourly_error"] = "endpoint returned an empty series"
            else:
                res["hourly"] = str(dest)
        except Exception as e:                              # noqa: BLE001
            res["hourly_error"] = f"{type(e).__name__}: {e}"

    if spec.get("absorbing_coin"):
        try:
            p = fetch_llama_hourly(spec["absorbing_coin"], int(spec["llama_start"]),
                                   int(spec.get("llama_span", 200)), out_dir,
                                   timeout=timeout)
            dest = series_path(out_dir, name, "absorbing_1h")
            p.replace(dest)
            if len(load_series(dest)) == 0:
                dest.unlink()
                res["absorbing_error"] = "endpoint returned an empty series"
            else:
                res["absorbing"] = str(dest)
        except Exception as e:                              # noqa: BLE001
            res["absorbing_error"] = f"{type(e).__name__}: {e}"

    if spec.get("stablecoin_id") is not None:
        try:
            p = fetch_llama_supply(int(spec["stablecoin_id"]), out_dir,
                                   timeout=timeout)
            p.replace(series_path(out_dir, name, "supply"))
            res["supply"] = str(series_path(out_dir, name, "supply"))
        except Exception as e:                              # noqa: BLE001
            res["supply_error"] = f"{type(e).__name__}: {e}"

    return res

from asv.market import compute_indicators, label_depegs, sensitivity


def series(prices, step=60, t0=1_650_000_000):
    return [(t0 + i * step, p) for i, p in enumerate(prices)]


def test_short_dip_is_not_a_depeg():
    s = series([1.0] * 10 + [0.985] * 3 + [1.0] * 10)
    assert label_depegs(s, 0.99, min_minutes=5) == []


def test_sustained_dip_is_a_depeg():
    s = series([1.0] * 10 + [0.985] * 8 + [1.0] * 10)
    ev = label_depegs(s, 0.99, min_minutes=5)
    assert len(ev) == 1
    assert ev[0].duration_min >= 5
    assert ev[0].min_price == 0.985


def test_severity_tiers_and_state():
    s = series([1.0] * 5 + [0.70] * 20)
    assert label_depegs(s, 0.80, 5, "failure")
    ind = compute_indicators(s, cfg_thresholds={})
    assert ind.state == "collapse"
    assert ind.alerts


def test_supply_hyperinflation_raises_an_alert():
    s = series([1.0] * 100)
    sup = series([1e9] * 50 + [5e9] * 50)
    ind = compute_indicators(s, absorbing_supply=sup,
                             cfg_thresholds={"supply_growth_window_hours": 1})
    assert ind.supply_growth_24h > 0.5
    assert any("absorbing supply" in a for a in ind.alerts)


def test_sensitivity_is_monotone_in_threshold():
    s = series([1.0] * 10 + [0.93] * 20 + [1.0] * 10)
    out = sensitivity(s, [0.99, 0.95, 0.90], min_minutes=5)
    assert out["0.99"]["events"] == 1
    assert out["0.95"]["events"] == 1
    assert out["0.9"]["events"] == 0


# --- regressions from the behavioural-track audit ---------------------------
DAY = 86400


def test_a_data_gap_does_not_weld_two_episodes_into_one():
    """Six minutes below peg, a three-day hole, six more minutes below peg."""
    from asv.market import label_depegs
    s = [(i * 60, 0.97) for i in range(6)]
    s += [(3 * DAY + i * 60, 0.97) for i in range(6)]
    s += [(3 * DAY + 600, 1.00)]
    ev = label_depegs(s, threshold=0.99, min_minutes=5)
    assert len(ev) == 2, "a hole in the data must break the run, not extend it"
    assert all(e.duration_min < 60 for e in ev), \
        "duration must come from contiguous samples, not span the gap"


def test_contiguous_run_is_still_one_event():
    from asv.market import label_depegs
    s = [(i * 60, 0.97) for i in range(12)] + [(12 * 60, 1.0)]
    ev = label_depegs(s, threshold=0.99, min_minutes=5)
    assert len(ev) == 1 and ev[0].duration_min == 12


def test_lead_time_never_credits_an_alert_from_a_previous_episode():
    """`prior[0]` used to be the first alert in the whole series."""
    from asv.market import DepegEvent
    from asv.prevent import Alert, lead_time
    alerts = [Alert(1_000_000, "stressed", []),
              Alert(1_000_000 + 30 * DAY, "stressed", [])]
    events = [DepegEvent("depeg", 1_000_000 + 1 * DAY, 1_000_000 + 1 * DAY + 600, 10, .97),
              DepegEvent("depeg", 1_000_000 + 31 * DAY, 1_000_000 + 31 * DAY + 600, 10, .97)]
    lt = lead_time(alerts, events)
    assert lt["events"][1]["lead_minutes"] == 1440, \
        "the second event must use its own precursor, not the 31-day-old blip"
    assert lt["median_lead_minutes"] == 1440


def test_lead_time_respects_the_lookback_bound():
    from asv.market import DepegEvent
    from asv.prevent import Alert, lead_time
    ev = [DepegEvent("depeg", 10 * DAY, 10 * DAY + 600, 10, 0.97)]
    stale = [Alert(1, "stressed", [])]        # ~10 days early: not a warning
    assert lead_time(stale, ev)["events"][0]["lead_minutes"] is None
    fresh = [Alert(10 * DAY - 3600, "stressed", [])]
    assert lead_time(fresh, ev)["events"][0]["lead_minutes"] == 60


def test_indicator_window_is_time_based_not_sample_based():
    """prices[-1440:] is 24h on minute data but 60 days on hourly data."""
    from asv.market import compute_indicators
    hourly = [(i * 3600, 0.90 if i < 5 else 1.00) for i in range(24 * 30)]
    assert compute_indicators(hourly, cfg_thresholds={}).state == "normal", \
        "a depeg 29 days ago must not latch today's state"
    latched = compute_indicators(
        hourly, cfg_thresholds={"indicator_window_minutes": 60 * 24 * 60})
    assert latched.state == "active_depeg"


def test_zero_supply_baseline_is_undefined_not_infinite_growth():
    from asv.market import compute_indicators
    ind = compute_indicators([(0, 1.0)],
                             absorbing_supply=[(0, 0.0), (90000, 5.89e12)],
                             cfg_thresholds={})
    g = ind.supply_growth_24h
    assert g != g, "a zero baseline must be NaN, not the entire supply as 'growth'"


def test_sensitivity_uses_the_same_sample_floor_as_the_events():
    """The sweep must re-label with the pipeline's floor, not a weaker one.

    A single hourly print below the threshold opens an episode when the floor
    is 1. If the sweep uses 1 while the reported events use 2, the row at the
    headline threshold contradicts the event list in the same results file.
    """
    s = [(i * 3600, 1.0) for i in range(5)]
    s[2] = (2 * 3600, 0.985)                    # one lone dip, never confirmed
    assert sensitivity(s, [0.99], min_minutes=5, min_samples=1)["0.99"]["events"] == 1
    assert sensitivity(s, [0.99], min_minutes=5, min_samples=2)["0.99"]["events"] == 0
    assert len(label_depegs(s, 0.99, 5, min_samples=2)) == 0

"""Phase 10 figures, rendered from `phase9_report.json` (static PNGs for the paper).

Forms follow the data's job: injection ASR is one magnitude per (attack tier, defense) cell, so a
single-hue heatmap with every value printed; the evasion result is change along a strength axis, so
lines with direct end labels; false alarms and latency are single-series magnitudes, so bars.
Categorical colours come from the validated reference palette in fixed order; identity is never
colour-alone (markers + direct labels), and the report JSON is the table view.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402

SURFACE = "#fcfcfb"
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
GRID = "#e6e5e1"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]  # slots 1-4, fixed order
MARKERS = ["o", "s", "^", "D"]
BLUE_RAMP = LinearSegmentedColormap.from_list(
    "seq_blue", ["#cde2fb", "#86b6ef", "#3987e5", "#1c5cab", "#0d366b"]
)

DEFENSE_LABELS = {
    "undefended": "Undefended",
    "sanitizer": "8a sanitizer",
    "consistency": "Consistency\n(prior art)",
    "provenance": "8b provenance",
    "provenance_replay": "8b + replay",
    "twin_ablated": "Twin ablated",
}
TIER_LABELS = {
    "7a_naive": "7a naive",
    "7b_grounding_aware": "7b grounding-aware",
    "7b_adaptive": "7b adaptive",
    "held_out_payloads": "Held-out payloads",
}


def _style(ax: plt.Axes) -> None:
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=TEXT_SECONDARY, labelsize=9)
    ax.grid(True, axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _figure(width: float, height: float) -> tuple[plt.Figure, plt.Axes]:
    fig, ax = plt.subplots(figsize=(width, height), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    _style(ax)
    return fig, ax


def _title(ax: plt.Axes, title: str, subtitle: str) -> None:
    ax.set_title(title, loc="left", fontsize=12, color=TEXT_PRIMARY, pad=22, fontweight="bold")
    ax.text(0, 1.02, subtitle, transform=ax.transAxes, fontsize=8.5, color=TEXT_SECONDARY)


def _save(fig: plt.Figure, path: Path) -> Path:
    fig.tight_layout()
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)
    return path


def injection_heatmap(report: dict[str, Any], out: Path) -> Path | None:
    tiers = (report.get("injection") or {}).get("tiers") or {}
    held = (report.get("generalization") or {}).get("payloads") or {}
    rows = {**tiers, **({"held_out_payloads": held} if held else {})}
    defenses = (report.get("injection") or {}).get("defenses") or list(DEFENSE_LABELS)
    if not rows:
        return None

    grid, labels = [], []
    for tier, cells in rows.items():
        grid.append([(cells.get(d) or {}).get("asr") for d in defenses])
        labels.append(TIER_LABELS.get(tier, tier))

    fig, ax = _figure(8.2, 1.1 + 0.62 * len(rows))
    ax.grid(False)
    values = [[v if v is not None else float("nan") for v in row] for row in grid]
    ax.imshow(values, cmap=BLUE_RAMP, vmin=0, vmax=1, aspect="auto")
    for i, row in enumerate(grid):
        for j, v in enumerate(row):
            attempts = (rows[list(rows)[i]].get(defenses[j]) or {}).get("attempts", 0)
            text = f"{v:.2f}" if v is not None else f"n={attempts}\nwithheld"
            dark_cell = v is not None and v >= 0.55
            ax.text(j, i, text, ha="center", va="center", fontsize=9,
                    color="#ffffff" if dark_cell else TEXT_PRIMARY)
    ax.set_xticks(range(len(defenses)), [DEFENSE_LABELS.get(d, d) for d in defenses], fontsize=8.5)
    ax.set_yticks(range(len(labels)), labels, fontsize=9)
    ax.tick_params(length=0)
    for side in ax.spines.values():
        side.set_visible(False)
    _title(ax, "Injection attack success rate by defense",
           "Share of attempts cleared (`ignore`) among flows the undefended agent caught. "
           "0 = attack stopped.")
    return _save(fig, out)


def evasion_curve(report: dict[str, Any], out: Path) -> Path | None:
    curve = (report.get("evasion") or {}).get("curve") or []
    if len(curve) < 2:
        return None
    series = [
        ("ml_evasion_in_training", "ML, evasion in training"),
        ("ml_zero_day", "ML, zero-day"),
        ("agent", "Agent"),
        ("ensemble_or_flag", "Ensemble (or_flag)"),
    ]
    fig, ax = _figure(7.2, 4.2)
    xs_all = [row["strength"] for row in curve]
    for idx, (key, label) in enumerate(series):
        points = [
            (row["strength"], row[key]["asr"]) for row in curve
            if (row.get(key) or {}).get("asr") is not None
        ]
        if not points:
            continue
        xs, ys = zip(*points, strict=True)
        ax.plot(xs, ys, color=SERIES[idx], linewidth=2, marker=MARKERS[idx], markersize=6,
                markeredgecolor=SURFACE, markeredgewidth=1.5, label=label)
        ax.annotate(label, (xs[-1], ys[-1]), xytext=(8, 0), textcoords="offset points",
                    va="center", fontsize=8.5, color=TEXT_PRIMARY)
    ax.set_xlim(min(xs_all) - 0.03, max(xs_all) + 0.35)
    ax.set_ylim(-0.03, 1.05)
    ax.set_xlabel("Evasion strength", color=TEXT_SECONDARY, fontsize=9)
    ax.set_ylabel("Attack success rate", color=TEXT_SECONDARY, fontsize=9)
    ax.legend(frameon=False, fontsize=8.5, loc="upper left", labelcolor=TEXT_PRIMARY)
    _title(ax, "Phase 6 evasion: attack success vs strength",
           "Real reshaped traffic. Points with too few flows for a rate are omitted.")
    return _save(fig, out)


def _hbar(
    names: list[str], values: list[float], labels: list[str], out: Path, title: str, subtitle: str,
    xlabel: str,
) -> Path:
    fig, ax = _figure(7.2, 1.2 + 0.42 * len(names))
    ax.grid(True, axis="x", color=GRID, linewidth=0.8)
    ax.grid(False, axis="y")
    ax.barh(range(len(names)), values, color=SERIES[0], height=0.6)
    for i, (v, text) in enumerate(zip(values, labels, strict=True)):
        ax.text(v, i, f"  {text}", va="center", fontsize=8.5, color=TEXT_PRIMARY)
    ax.set_yticks(range(len(names)), names, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel(xlabel, color=TEXT_SECONDARY, fontsize=9)
    ax.set_xlim(0, max(values + [1e-9]) * 1.25)
    _title(ax, title, subtitle)
    return _save(fig, out)


def false_alarm_bars(report: dict[str, Any], out: Path) -> Path | None:
    fa = report.get("false_alarms") or {}
    by = fa.get("by_defense") or {}
    if not by:
        return None
    names = [DEFENSE_LABELS.get(k, k).replace("\n", " ") for k in by]
    values = [v["false_alarms"] / v["flows"] if v["flows"] else 0.0 for v in by.values()]
    labels = [
        f"{v['false_alarms']}/{v['flows']}" + ("" if v["rate"] is not None else " (rate withheld)")
        for v in by.values()
    ]
    return _hbar(names, values, labels, out, "False alarms on honest cleared benign flows",
                 f"{fa.get('honest_cleared_flows', 0)} benign test flows the agent correctly "
                 "cleared; share each defense wrongly overrides.", "False-alarm share")


def latency_bars(report: dict[str, Any], out: Path) -> Path | None:
    layers = (report.get("latency") or {}).get("layers") or {}
    items = [(k, v["mean_ms"]) for k, v in layers.items() if v.get("mean_ms") is not None]
    if not items:
        return None
    items.sort(key=lambda kv: -kv[1])
    return _hbar([k.replace("_", " ") for k, _ in items], [v for _, v in items],
                 [f"{v:.2f} ms" for _, v in items], out, "Mean cost per call, by layer",
                 f"Provider: {report.get('provider')}. Replay re-runs the agent.",
                 "Milliseconds")


def render_all(report: dict[str, Any], figures_dir: Path) -> list[Path]:
    figures_dir.mkdir(parents=True, exist_ok=True)
    made = [
        injection_heatmap(report, figures_dir / "injection_asr.png"),
        evasion_curve(report, figures_dir / "evasion_curve.png"),
        false_alarm_bars(report, figures_dir / "false_alarms.png"),
        latency_bars(report, figures_dir / "latency.png"),
    ]
    return [p for p in made if p is not None]

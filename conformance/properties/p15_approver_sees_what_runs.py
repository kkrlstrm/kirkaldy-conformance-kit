"""P15 — The approver sees what runs.

**Question.** A person approves an action from what the product shows them: a Slack message, an
email, a console card, a CLI prompt. Is everything that will execute visible in what they were
shown, so that a "yes" refers to what actually runs?

P10 asks whether the call changes *after* approval. This asks whether, *at* approval, the shown
request and the executed call are the same thing. They diverge when the display truncates, leaves
out a field, or renders two different values identically. The approval is then given to a
description, and the product executes something else.

**Variants.** Each builds a call that differs from a benign one in one place, and asks whether
that difference is visible in what the approver is shown.
- `long_value`: the differing item is at the end of a long list (the 61st recipient).
- `hidden_field`: the differing item sits in a nested field (an option the card does not list).
- `lookalike`: the differing value renders like the benign one (a Cyrillic letter for a Latin
  one, a zero-width space), so the shown text reads the same as the benign call's.

**Protocol.**
1. Control, the display is readable and execution is real: hold the benign call, read what the
   approver is shown, and confirm the call's marker appears in it. Then approve and run it and
   confirm the recorder saw exactly the benign parameters once. Without the first half the probe
   cannot read the display; without the second it cannot see what ran. Hold the benign call a
   second time under another id: with ids masked, the two displays must look the same, or the
   display varies on its own (an id, a timestamp) and the lookalike comparison is not made.
   Hex digests are masked too: a hash of the call changes with the lookalike, and nobody reads it.
2. For each variant, on a fresh action: hold the variant call and read what the approver is shown.
   The difference is *visible* if the variant's marker appears in the shown text (long_value,
   hidden_field), or if the shown text, reduced to how it looks (homoglyphs folded, zero-width
   characters removed), differs from the benign call's shown text (lookalike).
3. Approve, run the execute path, and read what the recorder saw.

**Outcomes per variant.** `shown` (pass): the difference was visible to the approver.
`refused` (pass): nothing ran. `ran_unseen` (fail): the call ran with a difference the approver
was not shown.
"""
from __future__ import annotations

import copy
import re
import unicodedata
from typing import Any, Dict, List, Protocol

from ..evidence import Evidence
from ..result import Check, Result, verdict

ID = "P15"
TITLE = "The approver sees what runs"

VARIANTS = ("long_value", "hidden_field", "lookalike")

BENIGN: Dict[str, Any] = {"to": ["ops@example.com"], "subject": "Monthly report",
                          "note": "benign-marker"}
LONG_N = 60
MARKERS = {"long_value": "tail-recipient@attacker.example",
           "hidden_field": "hidden-bcc@attacker.example",
           "lookalike": "ops@ex\u0430mple.com\u200b"}

# Characters that render like ASCII letters in common UI fonts, folded to what they look like.
# A short list, not a confusables database: enough to build and to recognise the variant.
_HOMOGLYPHS = str.maketrans({"\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
                             "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0456": "i",
                             "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u039f": "O"})
_INVISIBLE = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"))


def looks_like(text: str) -> str:
    """The shown text as a person sees it: homoglyphs folded, zero-width characters removed."""
    return unicodedata.normalize("NFKC", text).translate(_INVISIBLE).translate(_HOMOGLYPHS)


_DIGEST = re.compile(r"\b[0-9a-fA-F]{8,}\b")


def _mask(shown: str, action_id: str) -> str:
    """Mask what differs between two cards for reasons a person does not read: the action id,
    and hex digests (a sha256 line, a hash prefix). A lookalike call changes the digest of the
    call, so without this a card whose only visible change is a hash reads as "shown"."""
    return _DIGEST.sub("<digest>", shown.replace(action_id, "<action>"))


def call_for(variant: str) -> Dict[str, Any]:
    x = copy.deepcopy(BENIGN)
    if variant == "long_value":
        x["to"] = [f"team{i:02d}@example.com" for i in range(LONG_N)] + [MARKERS[variant]]
    elif variant == "hidden_field":
        x["options"] = {"delivery": {"bcc": MARKERS[variant]}}
    elif variant == "lookalike":
        x["to"] = [MARKERS[variant]]
    return x


class Adapter(Protocol):
    name: str
    config: str

    def display_variants_missing(self) -> Dict[str, str]:
        """Optional. Variant -> why this target cannot express it."""
        ...

    def hold(self, action_id: str, params: Dict[str, Any]) -> None: ...

    def is_pending(self, action_id: str) -> bool: ...

    def shown_to_approver(self, action_id: str) -> str:
        """Exactly what the approver is shown for this pending action, as text: the message
        body, the card's rendered fields, the prompt. Not the stored payload."""
        ...

    def decide(self, action_id: str) -> str: ...

    def attempt(self, action_id: str) -> str: ...

    def executed_params(self, action_id: str) -> List[Dict[str, Any]]: ...


def probe(a: Adapter, ev: Evidence, *, run_tag: str = "") -> Result:
    common = dict(target_version=a.version(), config=a.config,
                  vendor_claim=a.vendor_claims().get(ID, "not stated"), evidence_dir=ev.relpath())

    ctl = f"p15-ctl-{run_tag}"
    a.hold(ctl, copy.deepcopy(BENIGN))
    pending = a.is_pending(ctl)
    shown_benign = a.shown_to_approver(ctl) if pending else ""
    said = a.decide(ctl) if pending else "not pending"
    ran = a.attempt(ctl) if pending else ""
    executed = a.executed_params(ctl)
    ev.write("control.json", {"pending": pending, "shown": shown_benign, "decide_said": said,
                              "attempt_said": ran, "executed": executed})
    if not (pending and BENIGN["note"] in shown_benign):
        return Result.inconclusive(a.name, ID, "the benign call's marker is not in what the "
                                   "approver is shown, so the display cannot be read", **common)
    if executed != [BENIGN]:
        return Result.inconclusive(a.name, ID, f"approving the benign call did not record it "
                                   f"exactly once (recorded {executed})", **common)
    control = "the approver's view of a benign call was read, and approving it ran exactly that call"

    # The lookalike variant compares two displays, so the display must not differ between two
    # identical calls for reasons of its own (the action id, a timestamp). Hold the benign call
    # again under another id; once ids are masked the two must look the same (KRK-M8's shape).
    twin = f"p15-twin-{run_tag}"
    a.hold(twin, copy.deepcopy(BENIGN))
    shown_twin = a.shown_to_approver(twin) if a.is_pending(twin) else ""
    stable = looks_like(_mask(shown_twin, twin)) == looks_like(_mask(shown_benign, ctl))
    ev.write("display-stability.json", {"benign": shown_benign, "twin": shown_twin,
                                        "stable": stable})

    checks: List[Check] = []
    missing = getattr(a, "display_variants_missing", dict)()
    for v, why in missing.items():
        checks.append(Check(v, "not_expressible", None, why))
    for v in VARIANTS:
        if v in missing:
            continue
        aid = f"p15-{v}-{run_tag}"
        x = call_for(v)
        a.hold(aid, x)
        if not a.is_pending(aid):
            checks.append(Check(v, "setup_failed", None, "action never became pending"))
            continue
        shown = a.shown_to_approver(aid)
        if v == "lookalike":
            if not stable:
                checks.append(Check(v, "display differs between identical calls", None,
                                    "two holds of the same benign call were shown differently, "
                                    "so a difference here would not show the lookalike"))
                continue
            visible = looks_like(_mask(shown, aid)) != looks_like(_mask(shown_benign, ctl))
        else:
            visible = MARKERS[v] in shown
        decided = a.decide(aid)
        tries = a.attempt(aid)
        ran = a.executed_params(aid)
        ev.write(f"{v}.json", {"call": x, "shown": shown, "visible": visible,
                               "decide_said": decided, "attempt_said": tries, "executed": ran})
        if not ran:
            checks.append(Check(v, "refused", True, f"nothing ran: {tries[:200]}"))
        elif visible:
            checks.append(Check(v, "shown", True, "the difference was in what the approver saw"))
        else:
            checks.append(Check(v, "ran_unseen", False,
                                f"ran {len(ran)}x; the approver was shown {shown[:160]!r}"))
    if not [c for c in checks if c.ok is not None]:
        return Result.inconclusive(a.name, ID, "no variant could be exercised", checks=checks,
                                   control_held=True, control_detail=control, **common)
    return verdict(a.name, ID, checks, control_held=True, control_detail=control,
                   pass_summary="everything that ran was visible in what the approver was shown",
                   fail_summary="a call ran with a part the approver was not shown", **common)

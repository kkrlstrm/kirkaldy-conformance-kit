import pytest


@pytest.fixture(autouse=True)
def _no_late_wait(monkeypatch):
    """Toys release held requests synchronously, so P1's late-arrival wait is dead time here."""
    monkeypatch.setattr("conformance.properties.p1_failure_direction.LATE_S", 0)


@pytest.fixture(autouse=True)
def _no_hold(monkeypatch):
    """P8 holds approvals for a minute against real targets; toys have nothing to wait for."""
    monkeypatch.setattr("conformance.properties.p8_wait_cost.HOLD_S", 0)


def _register_x1x5_toys() -> None:
    """P20's, P21's and P23's toys in `known_bad.toys.TOYS`, the one catalogue `test_known_bad.py`
    checks against the property list. Registered here, not by editing `known_bad/toys.py` or
    `tests/test_known_bad.py`: those are P1 to P15's hashed fixture files, and editing them
    would lapse those properties' verdicts. This file is in
    no property's hashed set."""
    from known_bad import toys

    def _standing(config: str):
        from known_bad.standing_toys import toy
        return toy(config)

    def _attenuation(config: str):
        from known_bad.attenuation_toys import toy
        return toy(config)

    def _reversal(config: str):
        from known_bad.reversal_toys import toy
        return toy(config)

    toys.TOYS.setdefault("P20", _standing)
    toys.TOYS.setdefault("P21", _attenuation)
    toys.TOYS.setdefault("P23", _reversal)


def _register_x9_toys() -> None:
    """P22's toys (`known_bad.ceiling_toys`), registered here for the same reason as P20's and
    P21's. A P22 configuration names its role: ``a-good``, ``b-bad:<flaw>`` and so on."""
    from known_bad import toys

    def _ceiling(config: str):
        from known_bad.ceiling_toys import toy
        return toy(config if config[:2] in ("a-", "b-") else f"a-{config}")

    toys.TOYS.setdefault("P22", _ceiling)


def _register_x2_toys() -> None:
    """P24's toys (`known_bad.mandate_toys`), registered here for the same reason as P20's to
    P23's: this file is in no property's hashed set."""
    from known_bad import toys

    def _mandate(config: str):
        from known_bad.mandate_toys import toy
        return toy(config)

    toys.TOYS.setdefault("P24", _mandate)


def _register_x6_toys() -> None:
    """P25's toys (`known_bad.disclosure_toys`), registered here for the same reason as P20's."""
    from known_bad import toys

    def _disclosure(config: str):
        from known_bad.disclosure_toys import toy
        return toy(config)

    toys.TOYS.setdefault("P25", _disclosure)


def _register_x11_toys() -> None:
    """P26's toys (`known_bad.translation_toys`), registered here for the same reason as P20's to
    P23's. The plain configurations `test_known_bad.py` asks for map onto topology T: ``good`` and
    ``no-control`` as named, ``bad`` onto ``bad:face_value@T``. The gate's own cases name their
    topology (``good@R``, ``bad:translated_only@R``)."""
    from known_bad import toys

    def _translation(config: str):
        from known_bad.translation_toys import toy
        if "@" not in config:
            config = {"bad": "bad:face_value"}.get(config, config) + "@T"
        return toy(config)

    toys.TOYS.setdefault("P26", _translation)


_register_x1x5_toys()
_register_x9_toys()
_register_x2_toys()
_register_x6_toys()
_register_x11_toys()

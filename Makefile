# The kit. Python 3.11+ and uv are the only requirements for the tests and the known-bad gate.
PY := .venv/bin/python
RUN ?= $(shell date -u +%Y%m%dT%H%M%S)
SEED ?=
SEEDARG = $(if $(SEED),--seed $(SEED))

.PHONY: setup test known-bad status seed-sweep run matrix targets

setup:           ## a venv with the kit's dependencies
	uv venv -q .venv && uv pip install -q -p .venv pytest "cryptography>=42" "pyjwt[crypto]>=2.8"

test:            ## the probes against their known-bad / known-good fixtures; no Docker, no network beyond loopback
	$(PY) -m pytest -q

known-bad:       ## record the known-bad gate [PROPS=P1,P2]; current properties are skipped (spec §3.5)
	$(PY) -m conformance known-bad --record $(if $(PROPS),-p $(PROPS))
	$(PY) -m conformance known-bad --record -p P18B

status:          ## each property's gate record: current, stale, failed or missing
	$(PY) -m conformance known-bad --status

seed-sweep:      ## the known-bad gate under a sweep of seeds (hours; tests/test_gate_seed_sweep.py) [PROPS=P20,P22]
	ACK_SEED_SWEEP=1 ACK_SEED_SWEEP_PROPS=$(PROPS) $(PY) -m pytest -q tests/test_gate_seed_sweep.py

targets:         ## the adapters under targets/ and their configurations
	$(PY) -m conformance targets

run:             ## make run TARGET=toys@P1-bad PROPS=P1 [RUN=id] [SEED=n]: record the gate, then probe
	$(PY) -m conformance known-bad --record $(if $(PROPS),-p $(PROPS))
	$(PY) -m conformance run $(TARGET) $(if $(PROPS),-p $(PROPS)) --run-id $(RUN) $(SEEDARG)

matrix:          ## make matrix RUN=id: results/<id>/MATRIX.md
	$(PY) -m conformance matrix $(RUN)

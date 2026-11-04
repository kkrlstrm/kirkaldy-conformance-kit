"""Known-bad and known-good toy B's for P25 (KRK-25, counterparty disclosure), in both profiles.

`X6-COUNTERPARTY-DISCLOSURE-DESIGN.md` §4.6. Each toy is an in-process B with a real recorder
path (its executor POSTs the request's values to the kit's recorder) and its own record table,
read back through its read path (`attribution_record`) and its store (`store_rows`).

**``a-issued``** (`ToyDisclosureB`). It pins each organisation's anchor and reads that
organisation's key statement (``/keys``) on every request, so it learns of a retired key at once.
It finds the agent's organisation by the statement that lists the request's signing key for
``request``; verifies the agent's own X3 authorisation over the exact bytes, once; verifies a
holder chain where one is presented (`standing.verify_holder_chain`), the leaf being the signer;
and reads the disclosure. ``good`` takes the principal only from a statement verified under a key
the root organisation designates for ``standing``, whose ``issuer`` is that organisation, whose
``audience`` is B, whose ``request_digest`` is the request's binding digest, and whose
``agent_key`` and ``actor`` are the request's signer; it refuses a request whose disclosure fails
any of these. It records the agent's own statement (signed by the agent, or unsigned) at the
``agent-asserted`` basis, and ignores request members for attribution. It records, as separate
facts, the actor (kind and id), the agent's key and organisation, and the principal at the level
the statement carries with the stating organisation; it labels the basis. It answers another agent
or another organisation about an operation with 404; it refuses an operation it states needs
disclosure without a valid one, and an operation it bars to agents; and it keeps the attribution
on the row, never through the live delegation. Its persons act directly with their own key.

**``good-strict``** also refuses any request carrying a principal member (header, query or body)
and any agent-asserted disclosure, and states so before the run (`strict_rules`; spec §3.10 rule
2). Both must pass.

**``b-held``** (`ToyHeldB`). The person at B's page consents, through a declared test route, for
one agent identity at one tenant (a counterparty company); B mints a consent user for the agent,
issues a signed consent credential naming it, the person's customer id and a pseudonym per tenant,
and records both identities on every row. An operation that needs approval waits for the person at
B's page; an approval the agent asserts is accepted and labelled ``agent-asserted``, one under the
consent's standing permission ``standing-permission``. B's answer to an agent carries a signed
statement with the pseudonym, never the customer id.

**Flaws** (`FLAWS`, `HELD_FLAWS`): one per form, each recording or answering wrongly, never
deleting what it was sent (KRK-M47). `FAILS` names the forms each is built to fail; the tests pin
the exact set. ``bad`` is ``records_caller_only``. ``info:stores_token`` keeps the raw disclosure on
the row and no attribution of its own (KRK-M188); ``no-control`` posts its effects where the
recorder never sees them.

Knobs (``tests/test_failure_modes_x6.py``) are listed in `KNOBS`.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from conformance import authz, bissuer, disclosure as dz, requester, standing
from conformance.authz import Presentation
from conformance.issuer import KEYS_PATH
from conformance.receipts import Keypair
from conformance.stand_in import AgentIdentity, ConsentRecord

B_ID = "did:web:b.example"
ENDPOINT = "/ops"
DIRECT_ENDPOINT = "/me"
PERSON_HEADER = "X-Toy-Person"
QUOTE = "toy statement, written before the run (known_bad/disclosure_toys.py)"
SOURCE = "documentation (the toy's own module docstring)"
OPS = {"crm.record.push": {"agreed": "named"}, "notes.append": {"agreed": "pairwise"},
       "case.open": {"agreed": "organisation"},
       "payments.send": {"agreed": "named", "requirement": "disclosure-required"},
       "admin.purge": {"agreed": "named", "requirement": "agents-barred"}}
HELD_OPS = {"crm.record.push": {"agreed": "named"}, "notes.append": {"agreed": "pairwise"},
            "payments.send": {"agreed": "named", "requirement": "disclosure-required"},
            "admin.purge": {"agreed": "named", "requirement": "agents-barred"},
            "transfer.approve": {"agreed": "named", "requirement": "approval-required"}}
LABELS = {"a-attested": "a-attested", "b-consent": "b-consent",
          "agent-asserted": "agent-asserted", "unattested": "unattested", "person": "person",
          "standing-permission": "standing-permission"}
TENANTS = ("t-1", "t-2")
VALUE_MEMBERS = ("operation", "ref", "amount", "recipient", "note")

FLAWS = ("records_caller_only", "records_principal_as_actor", "direct_as_last_agent",
         "drops_pairwise", "drops_commitment", "trusts_header_member", "trusts_body_member",
         "trusts_query_member", "disclosure_unbound", "agent_unchecked", "issuer_unchecked",
         "asserted_as_attested", "accepts_unsigned", "ignores_requirement", "ignores_bar",
         "answers_with_principal", "answers_other_counterparty",
         "attribution_via_live_delegation", "records_first_hop_agent",
         "records_leaf_org_principal")
HELD_FLAWS = ("records_caller_only", "records_principal_as_actor", "direct_as_last_agent",
              "drops_pairwise", "trusts_header_member", "trusts_body_member",
              "trusts_query_member", "labels_agent_approval_as_person",
              "labels_standing_as_person", "ignores_requirement", "ignores_bar",
              "answers_with_principal", "answers_other_counterparty", "global_pseudonym",
              "names_in_statement", "attribution_via_live_delegation")
FAILS = {
    "records_caller_only": {"principal_shown/named", "principal_shown/pairwise",
                            "principal_shown/organisation", "outlives_delegation/grant_ended",
                            "chain/two_hops", "chain/into_c"},
    "records_principal_as_actor": {"actor_shown/agent", "chain/two_hops", "chain/into_c"},
    "direct_as_last_agent": {"actor_shown/person_direct"},
    "drops_pairwise": {"principal_shown/pairwise"},
    "drops_commitment": {"principal_shown/organisation"},
    "trusts_header_member": {"asserted_principal/header"},
    "trusts_body_member": {"asserted_principal/body_member"},
    "trusts_query_member": {"asserted_principal/query"},
    "disclosure_unbound": {"foreign_disclosure/other_request"},
    "agent_unchecked": {"foreign_disclosure/other_agent"},
    "issuer_unchecked": {"foreign_disclosure/other_issuer"},
    "asserted_as_attested": {"self_asserted/agent_signed"},
    "accepts_unsigned": {"self_asserted/unsigned"},
    "ignores_requirement": {"missing_disclosure/required_absent", "self_asserted/agent_signed",
                            "self_asserted/unsigned"},
    "ignores_bar": {"missing_disclosure/agent_barred"},
    "answers_with_principal": {"level_exceeded/answer_to_other_agent"},
    "answers_other_counterparty": {"level_exceeded/answer_to_other_counterparty"},
    "attribution_via_live_delegation": {"outlives_delegation/grant_ended"},
    "records_first_hop_agent": {"chain/two_hops", "chain/into_c"},
    "records_leaf_org_principal": {"chain/into_c"},
}
"""The forms each ``a-issued`` flaw fails, exactly (pinned in the tests)."""
HELD_FAILS = {
    "records_caller_only": {"principal_shown/named", "principal_shown/pairwise",
                            "outlives_delegation/consent_revoked"},
    "records_principal_as_actor": {"actor_shown/agent"},
    "direct_as_last_agent": {"actor_shown/person_direct"},
    "drops_pairwise": {"principal_shown/pairwise"},
    "trusts_header_member": {"asserted_principal/header"},
    "trusts_body_member": {"asserted_principal/body_member"},
    "trusts_query_member": {"asserted_principal/query"},
    "labels_agent_approval_as_person": {"approval_basis/agent_asserted"},
    "labels_standing_as_person": {"approval_basis/standing_permission"},
    "ignores_requirement": {"missing_disclosure/required_absent"},
    "ignores_bar": {"missing_disclosure/agent_barred"},
    "answers_with_principal": {"level_exceeded/answer_to_other_agent"},
    "answers_other_counterparty": {"level_exceeded/answer_to_other_counterparty"},
    "global_pseudonym": {"level_exceeded/pseudonym_linkable"},
    "names_in_statement": {"level_exceeded/named_in_pairwise"},
    "attribution_via_live_delegation": {"outlives_delegation/consent_revoked"},
}
"""The forms each ``b-held`` flaw fails, exactly."""
KNOBS = ("fold_case", "declares_fold", "stores_body", "no_op_id", "records_owner",
         "levels_only_named", "refuses_required_for_agents", "bars_everyone",
         "executes_member", "names_field", "record_delay_s", "learns_end_late",
         "adapter_drops_unattested", "direct_with_disclosure", "records_channel",
         "remembers_principals", "tenants_share_key", "pseudonym_is_hash")
"""Settings for the failure-mode pins (`test_failure_modes_x6.py`), never used by the gate."""


class Refused(Exception):
    def __init__(self, code: int, reason: str) -> None:
        super().__init__(reason)
        self.code, self.reason = code, reason


def _post(url: str, doc: Dict[str, Any]) -> None:
    raw = json.dumps(doc, sort_keys=True).encode()
    req = urllib.request.Request(url, data=raw, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read()


def _strict(raw: bytes) -> Dict[str, Any]:
    def pairs(ps):
        d: Dict[str, Any] = {}
        for k, v in ps:
            if k in d:
                raise Refused(400, f"member {k!r} twice")
            d[k] = v
        return d
    try:
        v = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=pairs)
    except (ValueError, UnicodeDecodeError) as e:
        raise Refused(400, f"not JSON: {e}")
    if not isinstance(v, dict):
        raise Refused(400, "not an object")
    return v


class _Base:
    """What both toys share: the record table, the effect, the knobs."""

    def __init__(self, config: str, flaw: Optional[str], knobs: Dict[str, Any]) -> None:
        unknown = sorted(set(knobs) - set(KNOBS))
        if unknown:
            raise ValueError(f"unknown knobs {unknown}")
        self.config, self.flaw, self.k = config, flaw, dict(knobs)
        self.no_control = config.endswith("no-control")
        self.rec_url = ""
        self.rows: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.RLock()
        self.got: Dict[str, Dict[str, Any]] = {}
        self.seen_principals: set = set()
        self.written: Dict[str, float] = {}

    def version(self) -> str:
        return f"{self.name}@{self.config}"

    def vendor_claims(self) -> Dict[str, str]:
        return {}

    def not_applicable(self) -> Dict[str, str]:
        return {}

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def bind_recorder(self, url: str) -> str:
        self.rec_url = url
        return "the executor POSTs each effect to the recorder"

    def evidence_grade(self) -> str:
        return "b-store"

    def labels_basis(self) -> Dict[str, Any]:
        return {"labels": dict(LABELS), "quote": QUOTE, "source": SOURCE}

    def normalisation(self) -> Optional[Dict[str, Any]]:
        return {"case": "fold"} if self.k.get("declares_fold") else None

    def formats(self) -> List[str]:
        return [dz.SCHEMA]

    def classify(self, answer: Dict[str, Any]) -> str:
        s = answer.get("status")
        if s == 200:
            return "accepted"
        if s in (400, 401, 403, 404, 409):
            return "refused"
        return "error"

    def operation_of(self, answer: Dict[str, Any]) -> Optional[str]:
        if self.k.get("no_op_id"):
            return None
        return (answer.get("body") or {}).get("op_id")

    def received(self, pid: str) -> Optional[Dict[str, Any]]:
        return self.got.get(pid)

    def _execute(self, op_id: str, values: Dict[str, Any]) -> None:
        doc = {k: values[k] for k in VALUE_MEMBERS if k in values}
        if self.k.get("executes_member") and dz.ASSERT_MEMBER in values:
            doc["recipient"] = values[dz.ASSERT_MEMBER]
        path = "/elsewhere/effect/" if self.no_control else "/effect/"
        url = (self.rec_url.rsplit("/p25/", 1)[0] if self.no_control else self.rec_url)
        _post(f"{url}{path}{op_id}", doc)

    def _store(self, op_id: str, row: Dict[str, Any]) -> None:
        with self.lock:
            self.rows[op_id] = row
            self.written[op_id] = time.time()

    def _row(self, op_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            row = self.rows.get(op_id)
            at = self.written.get(op_id, 0.0)
        if row is None:
            return None
        if time.time() - at < float(self.k.get("record_delay_s") or 0.0):
            return None
        return row

    def _value(self, s: Optional[str]) -> Optional[str]:
        if s is None:
            return None
        return s.casefold() if self.k.get("fold_case") else s

    def strict_rules(self) -> Optional[Dict[str, Any]]:
        if self.config != "good-strict":
            return None
        return {"refuses": ["a request carrying an On-Behalf-Of header, an on_behalf_of query "
                            "parameter or an on_behalf_of body member",
                            "an agent-asserted or unsigned disclosure"],
                "stated": "in the toy's configuration, before the run (spec §3.10 rule 2)"}

    def _members(self, p: Presentation, values: Dict[str, Any]) -> Dict[str, str]:
        out = {}
        if dz.ASSERT_HEADER in p.headers:
            out["header"] = p.headers[dz.ASSERT_HEADER]
        if dz.QUERY + dz.ASSERT_MEMBER in p.headers:
            out["query"] = p.headers[dz.QUERY + dz.ASSERT_MEMBER]
        if dz.ASSERT_MEMBER in values:
            out["body_member"] = str(values[dz.ASSERT_MEMBER])
        return out

    def _member_principal(self, members: Dict[str, str]) -> Optional[str]:
        for where, flaw in (("header", "trusts_header_member"), ("body_member",
                                                                  "trusts_body_member"),
                            ("query", "trusts_query_member")):
            if self.flaw == flaw and where in members:
                return members[where]
        return None


# --------------------------------------------------------------------------- a-issued


class ToyDisclosureB(_Base):
    """A B that acts for other organisations' agents on A's disclosure (module docstring)."""

    name = "toy-disclosure"

    def __init__(self, config: str = "good", flaw: Optional[str] = None, **knobs: Any) -> None:
        if config == "bad" and flaw is None:
            flaw = "records_caller_only"
        if flaw is not None and flaw not in FLAWS:
            raise ValueError(f"unknown flaw {flaw!r}")
        cfg = config if flaw is None else f"bad:{flaw}"
        super().__init__(cfg, flaw, knobs)
        self.stores_token = config == "info:stores_token"
        self.strict = config == "good-strict"
        self.orgs: Dict[str, Dict[str, Any]] = {}
        self.persons: Dict[str, bytes] = {}
        self.used: set = set()
        self.live: Dict[str, Dict[str, Any]] = {}
        self.last_agent: Dict[str, Dict[str, Any]] = {}
        self.old_principals: set = set()

    # statements ------------------------------------------------------------------------------

    def disclosure_profile(self) -> str:
        return "a-issued"

    def agreement(self) -> Dict[str, Any]:
        return {"counterparty": B_ID, "endpoints": [ENDPOINT], "tenants": []}

    def levels(self) -> Dict[str, Any]:
        out = {}
        for op, d in OPS.items():
            if self.k.get("levels_only_named") and d["agreed"] != "named":
                continue
            out[op] = {"supported": ["named"] if self.k.get("levels_only_named")
                       else ["named", "pairwise", "organisation"],
                       "agreed": d["agreed"], "quote": QUOTE, "source": SOURCE}
        return out

    def requirements(self) -> Dict[str, Any]:
        return {op: {"requirement": d["requirement"], "quote": QUOTE, "source": SOURCE}
                for op, d in OPS.items() if d.get("requirement")}

    def pseudonyms(self) -> Optional[Dict[str, Any]]:
        return None

    def direct_path(self) -> Dict[str, Any]:
        return {"how": "the person's own key, enrolled at B", "endpoint": DIRECT_ENDPOINT,
                "quote": QUOTE, "source": SOURCE}

    def issuers(self) -> int:
        return 3

    def accepts_holder_hops(self) -> bool:
        return True

    def attribution_field(self) -> str:
        """Only the ``names_field`` knob defines a meaning for this; the probe never calls it
        (KRK-M176)."""
        return "$.record.received_at"

    # binding ---------------------------------------------------------------------------------

    def bind_requester(self, anchor: Dict[str, Any], source_url: str) -> str:
        with self.lock:
            self.old_principals |= self.seen_principals
            self.seen_principals = set()
        self.orgs[anchor["issuer"]] = {"anchor": dict(anchor["anchor"]), "url": source_url}
        return "pinned the anchor; B reads the key statement on every request"

    def bind_peer(self, anchor: Dict[str, Any], source_url: str) -> str:
        self.orgs[anchor["issuer"]] = {"anchor": dict(anchor["anchor"]), "url": source_url}
        return "pinned the anchor; B reads the key statement on every request"

    def enrol_person(self, principal: str, kid: str, public: bytes) -> str:
        self.persons[principal] = bytes(public)
        return "a person account at B with the person's own key"

    def end_delegation(self, agent: str, *, by: str, **kw: Any) -> str:
        return "B reads A's key statement on every request"

    # key statements --------------------------------------------------------------------------

    def _keyset(self, issuer: str) -> Optional[Dict[str, Any]]:
        o = self.orgs[issuer]
        src = requester.local_source(o["url"])
        if src is None:
            return None
        code, tok = src.fetch_local(KEYS_PATH, "b")
        if code != 200:
            return None
        v = standing.verify(tok, o["anchor"], standing.KEYSET_TYP)
        if not v.ok or v.claims.get("issuer") != issuer:
            return None
        return v.claims

    def _alive(self, ks: Dict[str, Any], kid: str, purpose: str) -> bool:
        """Whether `kid` is the organisation's for `purpose` now. The ``learns_end_late`` knob
        reads a retired key as still active: B has not learned of the end (KRK-M180)."""
        st = standing.key_state(ks, kid, purpose, time.time())[0]
        return st == "a-key" or (bool(self.k.get("learns_end_late")) and st == "retired")

    def _keysets(self) -> Dict[str, Dict[str, Any]]:
        return {i: ks for i in self.orgs for ks in [self._keyset(i)] if ks is not None}

    def _org_of(self, kid: str, purpose: str, kss: Dict[str, Dict[str, Any]]) -> Optional[str]:
        for issuer, ks in kss.items():
            if self._alive(ks, kid, purpose):
                return issuer
        return None

    # the entry point -------------------------------------------------------------------------

    def present(self, p: Presentation) -> Dict[str, Any]:
        h = dict(p.headers)
        if self.k.get("adapter_drops_unattested") and dz.HEADER in h:
            hdr = standing.header_of(h[dz.HEADER])
            if hdr.get("alg") == "none" or not str(hdr.get("kid", "")).startswith("standing-"):
                h.pop(dz.HEADER)
        self.got[p.pid] = {"headers": h, "request": p.request}
        try:
            if PERSON_HEADER in h:
                return self._person(p, h)
            return self._agent(p, h)
        except Refused as e:
            return {"status": e.code, "body": {"status": "refused", "reason": e.reason}}

    def _auth(self, p: Presentation, kss: Dict[str, Dict[str, Any]]
              ) -> Tuple[str, str, str, Dict[str, Any]]:
        """(subject, kid, the organisation listing the key, the authorisation's claims)."""
        kid = standing.header_of(p.authorisation).get("kid") if p.authorisation else None
        if not kid:
            raise Refused(401, "no authorisation")
        org = self._org_of(kid, "request", kss)
        if org is None:
            raise Refused(401, "the signing key is in no pinned organisation's statement for "
                               "request")
        pub = standing.keys_of(kss[org])[kid]
        v = authz.verify_authorisation(p.authorisation, {kid: pub})
        if not v.ok:
            raise Refused(401, f"authorisation: {v.reason}")
        c = v.claims
        if c["audience"].get("counterparty") != B_ID:
            raise Refused(403, "authorisation for another audience")
        try:
            dig = authz.binding_digest(p.request)
        except authz.NotBindable as e:
            raise Refused(400, f"not bindable: {e}")
        if c["binding"].get("request_digest") != dig:
            raise Refused(403, "the request is not the one authorised")
        with self.lock:
            if c["authorisation_id"] in self.used:
                raise Refused(409, "authorisation already used")
            self.used.add(c["authorisation_id"])
        return c["issuer"], kid, org, c

    def _chain(self, h: Dict[str, str], subject: str, kid: str,
               kss: Dict[str, Dict[str, Any]]) -> Tuple[Optional[str], Optional[str]]:
        """(root organisation, root subject) of a presented holder chain, or (None, None)."""
        if requester.GRANT_HEADER not in h:
            return None, None
        toks = [h[requester.GRANT_HEADER]] + [t for t in h.get(requester.CHAIN_HEADER, "")
                                               .split(",") if t]
        hops, why = standing.verify_holder_chain(toks, kss)
        if why:
            raise Refused(403, f"chain: {why}")
        leaf = hops[0].claims
        if leaf.get("subject") != subject or (leaf.get("agent_key") or {}).get("kid") != kid:
            raise Refused(403, "the request is not signed by the chain's leaf")
        return str(hops[-1].claims["issuer"]), str(hops[-1].claims["subject"])

    def _disclosure(self, tok: Optional[str], *, kid: str, subject: str, agent_org: str,
                    root_org: str, digest: str, kss: Dict[str, Dict[str, Any]]
                    ) -> Tuple[Optional[Dict[str, Any]], str, Optional[str]]:
        """(claims, basis, the stating organisation); raises Refused for an invalid statement."""
        if not tok:
            return None, "unattested", None
        hdr = standing.header_of(tok)
        claims = dz.peek(tok)
        if dz.claims_problem(claims):
            raise Refused(400, f"disclosure: {dz.claims_problem(claims)}")
        signer: Optional[str] = None
        if hdr.get("alg") == "none":
            if self.flaw != "accepts_unsigned":
                return claims, "agent-asserted", None
            signer = str(claims.get("issuer"))
            if signer not in kss:
                raise Refused(403, "disclosure from an organisation B does not pin")
        else:
            dkid = hdr.get("kid")
            for issuer, ks in kss.items():
                st = standing.key_state(ks, dkid, "standing", time.time())[0]
                listed = dkid in standing.keys_of(ks)
                if st == "a-key" or (self.flaw == "asserted_as_attested" and listed):
                    signer = issuer
                    v = dz.verify(tok, {dkid: standing.keys_of(ks)[dkid]})
                    if not v.ok:
                        raise Refused(403, f"disclosure: {v.reason}")
                    break
            if signer is None:
                ak = standing.keys_of(kss[agent_org]).get(kid)
                if dkid == kid and ak is not None and dz.verify(tok, {kid: ak}).ok:
                    return claims, "agent-asserted", None
                raise Refused(403, "disclosure signed by no key B knows")
        if claims["issuer"] != signer:
            raise Refused(403, "the disclosure's issuer is not the organisation that signed it")
        if signer != root_org and self.flaw != "issuer_unchecked":
            raise Refused(403, "the disclosure is not from the organisation the agent acts for")
        if claims["audience"] != B_ID:
            raise Refused(403, "disclosure for another audience")
        if claims["request_digest"] != digest and self.flaw != "disclosure_unbound":
            raise Refused(403, "disclosure for another request")
        if self.flaw != "agent_unchecked":
            if claims["agent_key"] != kid or claims["actor"]["id"] != subject:
                raise Refused(403, "disclosure for another agent")
            if claims["actor"]["org"] != agent_org:
                raise Refused(403, "disclosure names another organisation for the agent")
        if claims["not_after"] < int(time.time() * 1000):
            raise Refused(403, "disclosure expired")
        return claims, "a-attested", signer

    def _agent(self, p: Presentation, h: Dict[str, str]) -> Dict[str, Any]:
        kss = self._keysets()
        subject, kid, agent_org, ac = self._auth(p, kss)
        values = _strict(p.request)
        op = values.get("operation")
        if op == "krk.read":
            raise Refused(400, "a read goes through answer_as")
        if op not in OPS:
            raise Refused(400, f"unknown operation {op!r}")
        root_org, root_subject = self._chain(h, subject, kid, kss)
        root_org = root_org or agent_org
        req = OPS[op].get("requirement")
        if self.k.get("bars_everyone") and req == "agents-barred":
            raise Refused(403, "the operation is closed")
        if req == "agents-barred" and self.flaw != "ignores_bar":
            raise Refused(403, "agents may not perform this operation")
        if self.k.get("refuses_required_for_agents") and req == "disclosure-required":
            raise Refused(403, "agents may not perform this operation here")
        claims, basis, stated_by = self._disclosure(
            h.get(dz.HEADER), kid=kid, subject=subject, agent_org=agent_org, root_org=root_org,
            digest=authz.binding_digest(p.request), kss=kss)
        if self.k.get("remembers_principals") and claims is not None:
            pid_ = json.dumps(claims["principal"], sort_keys=True)
            with self.lock:
                if pid_ in self.old_principals:
                    raise Refused(409, "this principal was seen in an earlier run")
                self.seen_principals.add(pid_)
        members = self._members(p, values)
        if self.strict and (members or basis == "agent-asserted"):
            raise Refused(403, "this B refuses principal members and agent-asserted statements")
        if req == "disclosure-required" and basis != "a-attested" and \
                self.flaw != "ignores_requirement":
            raise Refused(403, "this operation needs A's disclosure")
        op_id = f"op-{secrets.token_hex(8)}"
        self._execute(op_id, values)
        principal = None
        if claims is not None and not self.stores_token:
            pc = claims["principal"]
            val = pc.get("id") or pc.get("pseudonym") or pc.get("commitment")
            principal = {"level": pc["level"], "value": self._value(val),
                         "organisation": (agent_org if self.flaw == "records_leaf_org_principal"
                                          else (stated_by or claims["issuer"]))}
            if self.flaw == "records_caller_only" or \
                    (self.flaw == "drops_pairwise" and pc["level"] == "pairwise") or \
                    (self.flaw == "drops_commitment" and pc["level"] == "organisation"):
                principal = None
        mp = self._member_principal(members)
        if mp is not None:
            principal = {"level": "named", "value": mp, "organisation": agent_org}
        agent_id = subject
        if self.flaw == "records_first_hop_agent" and root_subject:
            agent_id = root_subject
        actor = {"kind": "agent", "id": agent_id, "key": kid if agent_id == subject else None,
                 "organisation": agent_org}
        if self.flaw == "records_principal_as_actor":
            actor = {"kind": "agent", "id": (principal or {}).get("value"), "key": None,
                     "organisation": agent_org}
        row = {"op_id": op_id, "operation": op, "request_ref": values.get("ref"),
               "actor": actor, "principal": principal,
               "basis": LABELS[basis] if principal else None,
               "received_at": time.time()}
        if self.k.get("records_owner"):
            row["principal"] = {"level": "named", "value": values.get("recipient"),
                                "organisation": None}
        if self.k.get("stores_body"):
            row["request_body"] = p.request.decode("utf-8")
        if self.k.get("records_channel"):
            row["channel"] = p.endpoint
        if self.stores_token and h.get(dz.HEADER):
            row["disclosure"] = h[dz.HEADER]
        if self.flaw == "attribution_via_live_delegation" and principal is not None:
            with self.lock:
                self.live[op_id] = {"kid": kid, "org": agent_org, "principal": principal}
            row["principal"] = {"via_delegation": kid}
        if claims is not None and claims["principal"]["level"] == "named":
            with self.lock:
                self.last_agent[claims["principal"]["id"]] = dict(actor)
        self._store(op_id, row)
        return {"status": 200, "body": {"op_id": op_id, "status": "executed"}}

    def _person(self, p: Presentation, h: Dict[str, str]) -> Dict[str, Any]:
        who = h[PERSON_HEADER]
        pub = self.persons.get(who)
        kid = standing.header_of(p.authorisation).get("kid") if p.authorisation else None
        if pub is None or not kid:
            raise Refused(401, "no such person")
        v = authz.verify_authorisation(p.authorisation, {kid: pub})
        if not v.ok or v.claims["issuer"] != who:
            raise Refused(401, "the person's signature does not verify")
        if v.claims["binding"].get("request_digest") != authz.binding_digest(p.request):
            raise Refused(403, "the request is not the one signed")
        values = _strict(p.request)
        op = values.get("operation")
        if op not in OPS:
            raise Refused(400, f"unknown operation {op!r}")
        if self.k.get("bars_everyone") and OPS[op].get("requirement") == "agents-barred":
            raise Refused(403, "the operation is closed")
        op_id = f"op-{secrets.token_hex(8)}"
        self._execute(op_id, values)
        row = {"op_id": op_id, "operation": op, "request_ref": values.get("ref"),
               "actor": {"kind": "person", "id": self._value(who), "key": None,
                         "organisation": None},
               "principal": {"level": "named", "value": self._value(who), "organisation": None},
               "basis": LABELS["person"], "received_at": time.time()}
        if self.flaw == "direct_as_last_agent":
            with self.lock:
                last = self.last_agent.get(who)
            if last:
                row["actor"] = dict(last)
                row["basis"] = LABELS["a-attested"]
        if self.k.get("records_channel"):
            row["channel"] = p.endpoint
        self._store(op_id, row)
        return {"status": 200, "body": {"op_id": op_id, "status": "executed"}}

    def direct_presentation(self, principal: str, raw: bytes, *, key: Keypair, pid: str,
                            endpoint: str) -> Presentation:
        ep = DIRECT_ENDPOINT if self.k.get("records_channel") else endpoint
        t = time.time()
        claims = authz.authorisation_claims(
            issuer=principal, audience={"counterparty": B_ID, "endpoint": ep, "tenant": None},
            operation=_strict(raw).get("operation", ""), binding=authz.exact_binding(raw),
            max_uses=1, not_before=authz.utc(t - 900), not_after=authz.utc(t + 900),
            decision_digest=None)
        h = {PERSON_HEADER: principal}
        if self.k.get("direct_with_disclosure"):
            h[dz.HEADER] = "copied.disclosure.token"
        return Presentation(pid=pid, endpoint=ep, tenant=None, request=raw,
                            authorisation=authz.sign_authorisation(claims, key), headers=h)

    # reads -----------------------------------------------------------------------------------

    def _resolved(self, row: Dict[str, Any]) -> Dict[str, Any]:
        out = json.loads(json.dumps(row))
        pr = out.get("principal")
        if isinstance(pr, dict) and "via_delegation" in pr:
            with self.lock:
                live = self.live.get(out["op_id"])
            ks = self._keyset(live["org"]) if live else None
            alive = ks is not None and self._alive(ks, live["kid"], "request")
            out["principal"] = live["principal"] if alive else None
        return out

    def attribution_record(self, op_id: str) -> Optional[Dict[str, Any]]:
        row = self._row(op_id)
        if row is None:
            return None
        out = self._resolved(row)
        out.pop("request_body", None)
        return out

    def store_rows(self, op_id: str) -> Optional[List[Dict[str, Any]]]:
        row = self._row(op_id)
        return [self._resolved(row)] if row is not None else None

    def answer_as(self, caller: Presentation, op_id: str) -> Dict[str, Any]:
        kss = self._keysets()
        try:
            subject, kid, org, _c = self._auth(caller, kss)
        except Refused as e:
            return {"status": e.code}
        row = self._row(op_id)
        if row is None:
            return {"status": 404}
        actor = row.get("actor") or {}
        mine = actor.get("key") == kid or actor.get("id") == subject
        same_org = actor.get("organisation") == org
        if mine or (self.flaw == "answers_with_principal" and same_org) or \
                (self.flaw == "answers_other_counterparty" and not same_org):
            return {"status": 200, "record": self._resolved(row)}
        return {"status": 404}


# --------------------------------------------------------------------------- b-held


ROUTE, CLIENT, PROOF, SESSION = "X-Toy-Route", "X-Toy-Client", "X-Toy-Proof", "X-Toy-Session"


def _b64e(b: bytes) -> str:
    return bissuer.b64e(b)


class ToyHeldHook:
    """The person at the toy's page, through its declared test route."""

    kind = "declared-test-route"

    def __init__(self, b: "ToyHeldB", person: str) -> None:
        self.b, self.person = b, person
        self.log: List[ConsentRecord] = []

    def _decide(self, handle: Dict[str, Any], decision: str, pair: str) -> ConsentRecord:
        shown = self.b._page(handle, self.person, decision)
        rec = ConsentRecord(pair=pair, identity=str(handle.get("client") or ""), hook=self.kind,
                            person=self.person, decision=decision, handle=dict(handle),
                            shown=shown, steps=[{"route": "POST /test/decide", "status": 200}],
                            at=time.time())
        self.log.append(rec)
        return rec

    def approve(self, handle: Dict[str, Any], *, pair: str = "") -> ConsentRecord:
        return self._decide(handle, "approved", pair)

    def decline(self, handle: Dict[str, Any], *, pair: str = "") -> ConsentRecord:
        return self._decide(handle, "declined", pair)

    def revoke(self, consent: str) -> Dict[str, Any]:
        return self.b._revoke(consent, self.person)


class ToyHeldAgent:
    """The stand-in agent at the toy (`stand_in.StandInAgent`); it decides nothing."""

    def __init__(self, b: "ToyHeldB", ident: AgentIdentity) -> None:
        self.b, self.ident = b, ident
        self.creds: Dict[Any, str] = {}
        self.consents: Dict[Any, str] = {}

    def identity(self) -> AgentIdentity:
        return self.ident

    def consent(self, hook: Any, *, tenant: Optional[str], pair: str,
                decision: str = "approve") -> ConsentRecord:
        cid = self.b._start(self.ident, tenant)
        handle = {"consent": cid, "client": self.ident.client_id, "tenant": tenant}
        rec = (hook.approve if decision == "approve" else hook.decline)(handle, pair=pair)
        tok = self.b._redeem(cid)
        if tok:
            self.creds[tenant] = tok
            self.consents[tenant] = cid
            rec.credential = bissuer.BObject("credential", cid, tok.encode(), True,
                                             tenant=tenant, issued_to=self.ident.client_id)
        return rec

    def _pres(self, route: str, body: bytes, *, pid: str, tenant: Optional[str], endpoint: str,
              credential: Optional[str], headers: Optional[Dict[str, str]] = None
              ) -> Presentation:
        h = dict(headers or {})
        sig = self.ident.sign(route.encode() + b"|" + hashlib.sha256(body).hexdigest().encode())
        h.update({ROUTE: route, CLIENT: self.ident.client_id, PROOF: _b64e(sig)})
        return Presentation(pid=pid, endpoint=endpoint, tenant=tenant, request=body,
                            authorisation=credential, headers=h)

    def request(self, raw: bytes, *, pid: str, tenant: Optional[str], endpoint: str):
        return self._pres("propose", raw, pid=pid, tenant=tenant, endpoint=endpoint,
                          credential=self.creds.get(tenant))

    def counter(self, obj, raw, *, pid, tenant, endpoint):
        raise NotImplementedError("P25 makes no counter-proposal")

    def read(self, answer: Dict[str, Any], *, endpoint: str) -> List[bissuer.BObject]:
        tok = (answer.get("body") or {}).get("object")
        if not tok:
            return []
        c = json.loads(bissuer.b64d(tok.split(".")[1]))
        return [bissuer.BObject("pending", c["id"], tok.encode(), True, terms=c.get("terms"),
                                issued_to=c.get("issued_to"), tenant=c.get("tenant"),
                                claims=c)]

    def person_needed(self, obj) -> Optional[Dict[str, Any]]:
        return {"object": obj.id, "client": self.ident.client_id}

    def complete(self, obj, *, pid, tenant, endpoint):
        return None

    def acceptance_body(self, obj, *, approval: str = "person") -> Dict[str, Any]:
        said = {"person": "person", "agent": "user", "standing": "standing"}[approval]
        return {"object": obj.id, "approved_by": said}

    def accept(self, obj, body: bytes, *, pid: str, tenant: Optional[str], endpoint: str,
               headers: Optional[Dict[str, str]] = None,
               credential_tenant: Optional[str] = None):
        return self._pres("accept", body, pid=pid, tenant=tenant, endpoint=endpoint,
                          credential=self.creds.get(credential_tenant or tenant),
                          headers=headers)

    def class_body(self, values: Dict[str, Any]) -> Dict[str, Any]:
        return dict(values)

    def class_use(self, body: bytes, *, pid: str, tenant: Optional[str], endpoint: str,
                  headers: Optional[Dict[str, str]] = None):
        return self._pres("use", body, pid=pid, tenant=tenant, endpoint=endpoint,
                          credential=self.creds.get(tenant), headers=headers)


class ToyHeldB(_Base):
    """A B that mints the agent's identity from the person's consent at its page."""

    name = "toy-held"

    def __init__(self, config: str = "b-held-good", flaw: Optional[str] = None,
                 **knobs: Any) -> None:
        if config == "b-held-bad" and flaw is None:
            flaw = "records_caller_only"
        if flaw is not None and flaw not in HELD_FLAWS:
            raise ValueError(f"unknown flaw {flaw!r}")
        cfg = config if flaw is None else f"b-held-bad:{flaw}"
        super().__init__(cfg, flaw, knobs)
        share = Keypair.generate("t-shared")
        self.keys = {t: (share if knobs.get("tenants_share_key") else Keypair.generate(
            f"{t}-{secrets.token_hex(3)}")) for t in TENANTS}
        self.secrets = {t: secrets.token_bytes(32) for t in TENANTS}
        self.global_secret = secrets.token_bytes(32)
        self.persons: Dict[str, Dict[str, str]] = {}
        self.sessions: Dict[str, str] = {}
        self.clients: Dict[str, Dict[str, Any]] = {}
        self.consents: Dict[str, Dict[str, Any]] = {}
        self.pending: Dict[str, Dict[str, Any]] = {}
        self.last_agent: Dict[str, Dict[str, Any]] = {}

    # statements ------------------------------------------------------------------------------

    def disclosure_profile(self) -> str:
        return "b-held"

    def authority(self) -> Dict[str, Any]:
        return {"issuer": "B", "shape": "consent-id", "hook": {"kind": "declared-test-route"}}

    def agreement(self) -> Dict[str, Any]:
        return {"counterparty": B_ID, "endpoints": [ENDPOINT], "tenants": list(TENANTS)}

    def levels(self) -> Dict[str, Any]:
        return {op: {"supported": ["named", "pairwise"], "agreed": d["agreed"], "quote": QUOTE,
                     "source": SOURCE} for op, d in HELD_OPS.items()}

    def requirements(self) -> Dict[str, Any]:
        return {op: {"requirement": d["requirement"], "quote": QUOTE, "source": SOURCE}
                for op, d in HELD_OPS.items() if d.get("requirement")}

    def pseudonyms(self) -> Dict[str, Any]:
        return {"scope": "per-counterparty", "unit": "tenant", "quote": QUOTE, "source": SOURCE}

    def direct_path(self) -> Dict[str, Any]:
        return {"how": "the person's own session at B", "quote": QUOTE, "source": SOURCE}

    # people, agents, keys --------------------------------------------------------------------

    def new_person(self) -> str:
        handle = f"test-person-{secrets.token_hex(4)} (fictitious, made by the toy)"
        self.persons[handle] = {"customer": f"Cu-{secrets.token_hex(6)}",
                                "session": f"ses-{secrets.token_hex(10)}"}
        self.sessions[self.persons[handle]["session"]] = handle
        return handle

    def hook(self, person: str) -> ToyHeldHook:
        return ToyHeldHook(self, person)

    def agent(self, n: int, identities: Optional[List[AgentIdentity]] = None
              ) -> List[ToyHeldAgent]:
        ids = identities or [AgentIdentity.fresh() for _ in range(n)]
        return [ToyHeldAgent(self, i) for i in ids]

    def published_keys(self, tenant: Any) -> Dict[str, Any]:
        k = self.keys[tenant]
        return {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": k.kid,
                          "x": _b64e(k.public_bytes())}]}

    def identities(self, rec: ConsentRecord) -> Dict[str, Any]:
        c = json.loads(bissuer.b64d(rec.credential.raw.decode().split(".")[1]))
        return {"agent": c["consent_user_id"], "principal_named": c["granted_by"],
                "principal_pairwise": c["user"]}

    def _pseudonym(self, customer: str, tenant: Any) -> str:
        if self.k.get("pseudonym_is_hash"):
            return hashlib.sha256(customer.encode()).hexdigest()
        secret = self.global_secret if self.flaw == "global_pseudonym" else self.secrets[tenant]
        return hmac.new(secret, customer.encode(), hashlib.sha256).hexdigest()

    def _sign(self, tenant: Any, claims: Dict[str, Any]) -> str:
        k = self.keys[tenant]
        h = _b64e(json.dumps({"alg": "EdDSA", "kid": k.kid, "typ": "toy-held+jws"},
                             sort_keys=True).encode())
        p = _b64e(json.dumps(claims, sort_keys=True).encode())
        return f"{h}.{p}.{_b64e(k.private.sign(f'{h}.{p}'.encode()))}"

    def _start(self, ident: AgentIdentity, tenant: Any) -> str:
        cid = f"cns-{secrets.token_hex(6)}"
        with self.lock:
            self.clients[ident.client_id] = ident.jwk()
            self.consents[cid] = {"client": ident.client_id, "tenant": tenant,
                                  "state": "pending", "person": None,
                                  "consent_user": f"cu-{secrets.token_hex(6)}"}
        return cid

    def _page(self, handle: Dict[str, Any], person: str, decision: str) -> Dict[str, Any]:
        with self.lock:
            if "consent" in handle:
                c = self.consents[handle["consent"]]
                c["state"] = "approved" if decision == "approved" else "declined"
                c["person"] = person
                return {"consent": "an agent acting for you at this company"}
            obj = self.pending[handle["object"]]
            if self.persons.get(person, {}).get("customer") == obj["customer"]:
                obj["approved"] = decision == "approved"
            return {"terms": obj["terms"]}

    def _redeem(self, cid: str) -> Optional[str]:
        with self.lock:
            c = self.consents[cid]
            if c["state"] != "approved":
                return None
            cust = self.persons[c["person"]]["customer"]
        return self._sign(c["tenant"], {"typ": "consent", "consent_id": cid,
                                        "consent_user_id": c["consent_user"],
                                        "client_id": c["client"], "tenant": c["tenant"],
                                        "granted_by": cust,
                                        "user": self._pseudonym(cust, c["tenant"]),
                                        "standing_permission": ["transfer.approve"],
                                        "iat": int(time.time())})

    def _revoke(self, cid: str, person: str) -> Dict[str, Any]:
        with self.lock:
            c = self.consents.get(cid)
            if c is None or c["person"] != person:
                return {"status": 404}
            c["state"] = "revoked"
        return {"status": 200, "consent": cid, "state": "revoked"}

    def end_delegation(self, agent: ToyHeldAgent, *, by: str, hook: Any = None,
                       tenant: Any = None) -> Dict[str, Any]:
        return hook.revoke(agent.consents[tenant])

    # the entry point -------------------------------------------------------------------------

    def present(self, p: Presentation) -> Dict[str, Any]:
        self.got[p.pid] = {"headers": dict(p.headers), "request": p.request}
        try:
            route = p.headers.get(ROUTE)
            if route == "person":
                return self._person(p)
            client, consent = self._client(p, need_consent=route != "bare")
            return {"use": self._use, "bare": self._use, "propose": self._propose,
                    "accept": self._accept}[route](p, client, consent)
        except Refused as e:
            return {"status": e.code, "body": {"status": "refused", "reason": e.reason}}
        except KeyError as e:
            return {"status": 400, "body": {"status": "refused", "reason": f"no route {e}"}}

    def _client(self, p: Presentation, *, need_consent: bool
                ) -> Tuple[str, Optional[Dict[str, Any]]]:
        from cryptography.exceptions import InvalidSignature
        cid = p.headers.get(CLIENT)
        jwk = self.clients.get(cid or "")
        if jwk is None:
            raise Refused(401, "unknown client")
        try:
            bissuer._public_key(jwk).verify(
                bissuer.b64d(p.headers.get(PROOF, "")),
                p.headers[ROUTE].encode() + b"|" + hashlib.sha256(p.request).hexdigest().encode())
        except (InvalidSignature, ValueError):
            raise Refused(401, "the client's proof does not verify")
        if not need_consent or not p.authorisation:
            if need_consent:
                raise Refused(401, "no consent")
            return cid, None
        v = bissuer.verify_b_object(p.authorisation, self.published_keys(p.tenant))
        if not v.ok:
            raise Refused(401, "not this tenant's consent")
        with self.lock:
            c = self.consents.get(v.claims["consent_id"])
        if c is None or c["client"] != cid or c["tenant"] != p.tenant:
            raise Refused(401, "the consent is not this client's at this tenant")
        if c["state"] != "approved":
            raise Refused(401, f"the consent is {c['state']}")
        return cid, {**c, "id": v.claims["consent_id"]}

    def _principal(self, consent: Dict[str, Any], level: str) -> Optional[Dict[str, Any]]:
        cust = self.persons[consent["person"]]["customer"]
        if self.flaw == "records_caller_only" or \
                (self.flaw == "drops_pairwise" and level == "pairwise"):
            return None
        val = cust if level == "named" else self._pseudonym(cust, consent["tenant"])
        return {"level": level, "value": val}

    def _row(self, op_id: str) -> Optional[Dict[str, Any]]:  # type: ignore[override]
        return super()._row(op_id)

    def _commit(self, op: str, values: Dict[str, Any], consent: Optional[Dict[str, Any]],
                client: str, p: Presentation, *, approval: Optional[str] = None
                ) -> Dict[str, Any]:
        op_id = f"op-{secrets.token_hex(8)}"
        self._execute(op_id, values)
        level = HELD_OPS[op]["agreed"]
        principal = self._principal(consent, level) if consent else None
        members = self._members(p, values)
        mp = self._member_principal(members)
        if mp is not None:
            principal = {"level": "named", "value": mp}
        actor = {"kind": "agent", "id": consent["consent_user"] if consent else None,
                 "client": client}
        if self.flaw == "records_principal_as_actor" and consent:
            actor = {"kind": "agent", "id": self.persons[consent["person"]]["customer"],
                     "client": None}
        row = {"op_id": op_id, "operation": op, "request_ref": values.get("ref"),
               "actor": actor, "principal": principal, "tenant": p.tenant,
               "basis": LABELS["b-consent"] if consent else LABELS["unattested"],
               "received_at": time.time()}
        if approval:
            row["approval"] = approval
        if self.flaw == "attribution_via_live_delegation" and consent:
            row["principal"] = {"via_consent": consent["id"], "level": level}
        if consent:
            with self.lock:
                self.last_agent[consent["person"]] = dict(actor)
        self._store(op_id, row)
        stmt = None
        if consent:
            cust = self.persons[consent["person"]]["customer"]
            user = cust if self.flaw == "names_in_statement" else \
                self._pseudonym(cust, consent["tenant"])
            stmt = self._sign(consent["tenant"], {"op": op_id, "aud": client,
                                                  "company": consent["tenant"], "user": user})
        return {"status": 200, "body": {"op_id": op_id, "status": "executed",
                                        "statement": stmt}}

    def _use(self, p: Presentation, client: str, consent: Optional[Dict[str, Any]]
             ) -> Dict[str, Any]:
        values = _strict(p.request)
        op = values.get("operation")
        if op not in HELD_OPS:
            raise Refused(400, f"unknown operation {op!r}")
        req = HELD_OPS[op].get("requirement")
        if req == "agents-barred" and self.flaw != "ignores_bar":
            raise Refused(403, "agents may not perform this operation")
        if req == "approval-required":
            raise Refused(403, "this operation needs an approved object")
        if consent is None and self.flaw != "ignores_requirement":
            raise Refused(401, "an agent acts here only under a consent")
        return self._commit(op, values, consent, client, p)

    def _propose(self, p: Presentation, client: str, consent: Optional[Dict[str, Any]]
                 ) -> Dict[str, Any]:
        values = _strict(p.request)
        if HELD_OPS.get(values.get("operation"), {}).get("requirement") != "approval-required":
            raise Refused(400, "no approval needed")
        oid = f"obj-{secrets.token_hex(6)}"
        cust = self.persons[consent["person"]]["customer"]
        with self.lock:
            self.pending[oid] = {"terms": values, "client": client, "consent": consent,
                                 "customer": cust, "approved": False, "used": False}
        tok = self._sign(p.tenant, {"id": oid, "terms": values, "issued_to": client,
                                    "tenant": p.tenant})
        return {"status": 202, "body": {"status": "pending", "object": tok}}

    def _accept(self, p: Presentation, client: str, consent: Optional[Dict[str, Any]]
                ) -> Dict[str, Any]:
        body = _strict(p.request)
        with self.lock:
            obj = self.pending.get(body.get("object"))
            if obj is None or obj["client"] != client or obj["used"]:
                raise Refused(409, "no such object")
            obj["used"] = True
        said = body.get("approved_by")
        if said == "person":
            if not obj["approved"]:
                raise Refused(403, "the person has not approved it")
            label = LABELS["person"]
        elif said == "user":
            label = LABELS["person"] if self.flaw == "labels_agent_approval_as_person" \
                else LABELS["agent-asserted"]
        elif said == "standing":
            label = LABELS["person"] if self.flaw == "labels_standing_as_person" \
                else LABELS["standing-permission"]
        else:
            raise Refused(400, "approved_by is person, user or standing")
        return self._commit(obj["terms"]["operation"], obj["terms"], obj["consent"], client, p,
                            approval=label)

    def classify(self, answer: Dict[str, Any]) -> str:
        if answer.get("status") == 202:
            return "pending"
        return super().classify(answer)

    def undisclosed_use(self, agent: ToyHeldAgent, body: bytes, *, pid: str, tenant: Any,
                        endpoint: str) -> Presentation:
        """The agent's own client credential and proof, without its consent."""
        return agent._pres("bare", body, pid=pid, tenant=tenant, endpoint=endpoint,
                           credential=None)

    def _person(self, p: Presentation) -> Dict[str, Any]:
        handle = self.sessions.get(p.headers.get(SESSION, ""))
        if handle is None:
            raise Refused(401, "no session")
        values = _strict(p.request)
        op = values.get("operation")
        if op not in HELD_OPS:
            raise Refused(400, f"unknown operation {op!r}")
        cust = self.persons[handle]["customer"]
        op_id = f"op-{secrets.token_hex(8)}"
        self._execute(op_id, values)
        row = {"op_id": op_id, "operation": op, "request_ref": values.get("ref"),
               "actor": {"kind": "person", "id": cust, "client": None},
               "principal": {"level": "named", "value": cust}, "tenant": None,
               "basis": LABELS["person"], "received_at": time.time()}
        if self.flaw == "direct_as_last_agent":
            with self.lock:
                last = self.last_agent.get(handle)
            if last:
                row["actor"] = dict(last)
        self._store(op_id, row)
        return {"status": 200, "body": {"op_id": op_id, "status": "executed"}}

    def direct_presentation(self, handle: str, raw: bytes, *, key: Any = None, pid: str,
                            endpoint: str) -> Presentation:
        return Presentation(pid=pid, endpoint=endpoint, tenant=None, request=raw,
                            authorisation=None,
                            headers={ROUTE: "person", SESSION: self.persons[handle]["session"]})

    # reads -----------------------------------------------------------------------------------

    def _resolved(self, row: Dict[str, Any]) -> Dict[str, Any]:
        out = json.loads(json.dumps(row))
        pr = out.get("principal")
        if isinstance(pr, dict) and "via_consent" in pr:
            with self.lock:
                c = self.consents.get(pr["via_consent"])
            out["principal"] = (self._principal({**c, "id": pr["via_consent"]}, pr["level"])
                                if c and c["state"] == "approved" else None)
        return out

    def attribution_record(self, op_id: str) -> Optional[Dict[str, Any]]:
        row = self._row(op_id)
        return self._resolved(row) if row is not None else None

    def store_rows(self, op_id: str) -> Optional[List[Dict[str, Any]]]:
        row = self._row(op_id)
        return [self._resolved(row)] if row is not None else None

    def answer_as(self, caller: ToyHeldAgent, op_id: str) -> Dict[str, Any]:
        row = self._row(op_id)
        if row is None:
            return {"status": 404}
        cid = caller.ident.client_id
        tenants = set(caller.creds)
        mine = (row.get("actor") or {}).get("client") == cid
        same = row.get("tenant") in tenants
        if mine or (self.flaw == "answers_with_principal" and same) or \
                (self.flaw == "answers_other_counterparty" and not same):
            return {"status": 200, "record": self._resolved(row)}
        return {"status": 404}


# --------------------------------------------------------------------------- the gate


def cases() -> List[Tuple[str, str]]:
    """Every gate configuration and its required outcome."""
    out = [("good", "pass"), ("bad", "fail"), ("no-control", "inconclusive"),
           ("good-strict", "pass"), ("b-held-good", "pass"), ("b-held-bad", "fail"),
           ("b-held-no-control", "inconclusive"), ("info:stores_token", "inconclusive")]
    out += [(f"bad:{f}", "fail") for f in FLAWS]
    out += [(f"b-held-bad:{f}", "fail") for f in HELD_FLAWS]
    return out


def toy(config: str, **knobs: Any) -> Any:
    if config.startswith("b-held-bad:"):
        return ToyHeldB("b-held-bad", config.split(":", 1)[1], **knobs)
    if config.startswith("b-held"):
        return ToyHeldB(config, **knobs)
    if config.startswith("bad:"):
        return ToyDisclosureB("bad", config.split(":", 1)[1], **knobs)
    return ToyDisclosureB(config, **knobs)

# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

from genlayer import *
import json
import hashlib
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

try:
    _Error = gl.vm.UserError
except Exception:
    _Error = Exception


def require(condition: bool, message: str) -> None:
    if not condition:
        raise _Error(message)


def canonical(value) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":")
    )


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

@allow_storage
@dataclass
class Policy:
    owner: str
    name: str
    rules: str
    active: bool
    policy_hash: str


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

@allow_storage
@dataclass
class Decision:
    policy_id: u256
    requester: str
    action_hash: str

    result: str
    confidence: u256

    reason_hash: str


# ---------------------------------------------------------------------------
# Natural-Language Permission Engine
# ---------------------------------------------------------------------------

class NaturalPermissionEngine(gl.Contract):

    policies: DynArray[Policy]
    decisions: DynArray[Decision]

    def __init__(self):
        pass

    # =======================================================================
    # CREATE POLICY
    # =======================================================================

    @gl.public.write
    def create_policy(
        self,
        name: str,
        rules: str
    ) -> int:

        creator = str(gl.message.sender_address)

        policy_name = name.strip()
        policy_rules = rules.strip()

        require(
            len(policy_name) > 0,
            "policy name is empty"
        )

        require(
            len(policy_rules) > 0,
            "policy rules are empty"
        )

        require(
            len(policy_rules) <= 8000,
            "policy too long"
        )

        policy_id = len(self.policies)

        policy_hash = hashlib.sha256(
            canonical({
                "name": policy_name,
                "rules": policy_rules
            }).encode()
        ).hexdigest()

        self.policies.append(
            Policy(
                owner=creator,
                name=policy_name,
                rules=policy_rules,
                active=True,
                policy_hash=policy_hash
            )
        )

        return policy_id

    # =======================================================================
    # DISABLE POLICY
    # =======================================================================

    @gl.public.write
    def disable_policy(
        self,
        policy_id: int
    ) -> str:

        require(
            0 <= policy_id < len(self.policies),
            "policy does not exist"
        )

        policy = self.policies[policy_id]

        sender = str(gl.message.sender_address)

        require(
            sender == policy.owner,
            "only policy owner can disable policy"
        )

        require(
            policy.active,
            "policy already disabled"
        )

        self.policies[policy_id] = Policy(
            owner=policy.owner,
            name=policy.name,
            rules=policy.rules,
            active=False,
            policy_hash=policy.policy_hash
        )

        return "DISABLED"

    # =======================================================================
    # EVALUATE PERMISSION
    # =======================================================================

    @gl.public.write
    def authorize(
        self,
        policy_id: int,
        requester: str,
        action: str,
        evidence: str
    ) -> str:

        require(
            0 <= policy_id < len(self.policies),
            "policy does not exist"
        )

        policy = self.policies[policy_id]

        require(
            policy.active,
            "policy is inactive"
        )

        request = requester.strip()
        requested_action = action.strip()
        supplied_evidence = evidence.strip()

        require(
            len(request) > 0,
            "requester is empty"
        )

        require(
            len(requested_action) > 0,
            "action is empty"
        )

        require(
            len(requested_action) <= 6000,
            "action too long"
        )

        require(
            len(supplied_evidence) <= 10000,
            "evidence too long"
        )

        rules = policy.rules

        # -------------------------------------------------------------------
        # Leader
        # -------------------------------------------------------------------

        def leader_fn():

            prompt = f"""
You are the authorization engine for an on-chain permission system.

Your job is to determine whether a REQUEST satisfies a POLICY.

You are NOT allowed to invent permissions.

You must follow the policy exactly as written.

POLICY NAME:
{policy.name}

POLICY:
{rules}

REQUESTER:
{request}

REQUESTED ACTION:
{requested_action}

EVIDENCE:
{supplied_evidence}

Evaluate the request using these principles:

1. Every explicit policy requirement must be satisfied.

2. If the policy requires evidence, the supplied evidence must actually
   support the requirement.

3. Do not assume missing information.

4. If the policy is ambiguous in a way that could materially affect
   authorization, choose REVIEW.

5. A request must never be ALLOW merely because it sounds reasonable.

6. If any mandatory requirement clearly fails, choose DENY.

7. Use REVIEW when the evidence is insufficient or the policy cannot
   reasonably determine the answer.

Return ONLY JSON:

{{
    "decision": "ALLOW | DENY | REVIEW",
    "confidence": 0,
    "failed_rules": [],
    "reason": "short explanation"
}}

confidence must be an integer from 0 to 1000.

Decision rules:

ALLOW:
All mandatory requirements are satisfied.

DENY:
At least one mandatory requirement is clearly violated.

REVIEW:
The policy is potentially satisfied but the available information
is insufficient or materially ambiguous.
"""

            result = gl.nondet.exec_prompt(
                prompt,
                response_format="json"
            )

            require(
                isinstance(result, dict),
                "invalid authorization response"
            )

            decision = str(
                result.get("decision", "")
            ).upper()

            require(
                decision in (
                    "ALLOW",
                    "DENY",
                    "REVIEW"
                ),
                "invalid authorization decision"
            )

            confidence = int(
                result.get("confidence", -1)
            )

            require(
                0 <= confidence <= 1000,
                "invalid confidence"
            )

            failed_rules = result.get(
                "failed_rules",
                []
            )

            require(
                isinstance(failed_rules, list),
                "invalid failed rules"
            )

            reason = str(
                result.get("reason", "")
            ).strip()

            require(
                len(reason) > 0,
                "missing reason"
            )

            return {
                "decision": decision,
                "confidence": confidence,
                "failed_rules": failed_rules,
                "reason": reason
            }

        # -------------------------------------------------------------------
        # Validator
        #
        # Validators independently evaluate the SAME policy/request.
        # We compare the important decision fields rather than demanding
        # identical natural-language explanations.
        # -------------------------------------------------------------------

        def validator_fn(leader_result):

            if not isinstance(
                leader_result,
                gl.vm.Return
            ):
                return False

            leader = leader_result.calldata

            if not isinstance(
                leader,
                dict
            ):
                return False

            own = leader_fn()

            if not isinstance(
                own,
                dict
            ):
                return False

            # The actual permission decision must agree.
            if own["decision"] != leader["decision"]:
                return False

            # If either side has very high confidence, prevent the other
            # validator from calling the same request REVIEW at low confidence.
            if (
                int(leader["confidence"]) >= 850
                and
                int(own["confidence"]) < 600
            ):
                return False

            if (
                int(own["confidence"]) >= 850
                and
                int(leader["confidence"]) < 600
            ):
                return False

            # The failed-rule field must have a valid structure.
            if not isinstance(
                own["failed_rules"],
                list
            ):
                return False

            if not isinstance(
                leader["failed_rules"],
                list
            ):
                return False

            return True

        # -------------------------------------------------------------------
        # Consensus
        # -------------------------------------------------------------------

        result = gl.vm.run_nondet_unsafe(
            leader_fn,
            validator_fn
        )

        require(
            isinstance(result, dict),
            "invalid consensus result"
        )

        decision = str(
            result["decision"]
        ).upper()

        confidence = int(
            result["confidence"]
        )

        reason = str(
            result["reason"]
        )

        # -------------------------------------------------------------------
        # Deterministic hashes
        # -------------------------------------------------------------------

        action_hash = hashlib.sha256(
            canonical({
                "requester": request,
                "action": requested_action,
                "evidence": supplied_evidence
            }).encode()
        ).hexdigest()

        reason_hash = hashlib.sha256(
            reason.encode()
        ).hexdigest()

        # -------------------------------------------------------------------
        # Store ONLY after consensus.
        # -------------------------------------------------------------------

        self.decisions.append(
            Decision(
                policy_id=u256(policy_id),
                requester=request,
                action_hash=action_hash,

                result=decision,
                confidence=u256(confidence),

                reason_hash=reason_hash
            )
        )

        return decision

    # =======================================================================
    # READ POLICY
    # =======================================================================

    @gl.public.view
    def get_policy(
        self,
        policy_id: int
    ) -> str:

        require(
            0 <= policy_id < len(self.policies),
            "policy does not exist"
        )

        p = self.policies[policy_id]

        return canonical({
            "policy_id": policy_id,
            "owner": p.owner,
            "name": p.name,
            "rules": p.rules,
            "active": p.active,
            "policy_hash": p.policy_hash
        })

    # =======================================================================
    # READ DECISION
    # =======================================================================

    @gl.public.view
    def get_decision(
        self,
        decision_id: int
    ) -> str:

        require(
            0 <= decision_id < len(self.decisions),
            "decision does not exist"
        )

        d = self.decisions[decision_id]

        return canonical({
            "decision_id": decision_id,
            "policy_id": int(d.policy_id),
            "requester": d.requester,
            "action_hash": d.action_hash,
            "result": d.result,
            "confidence": int(d.confidence),
            "reason_hash": d.reason_hash
        })

    # =======================================================================
    # COUNTS
    # =======================================================================

    @gl.public.view
    def policy_count(self) -> int:
        return len(self.policies)

    @gl.public.view
    def decision_count(self) -> int:
        return len(self.decisions)

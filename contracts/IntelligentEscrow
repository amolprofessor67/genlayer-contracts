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
# Escrow
# ---------------------------------------------------------------------------

@allow_storage
@dataclass
class Escrow:
    buyer: str
    seller: str

    task: str
    requirements: str
    submission_url: str

    amount: u256

    status: str
    score: u256

    decision_hash: str


# ---------------------------------------------------------------------------
# Requirement evaluation
# ---------------------------------------------------------------------------

@allow_storage
@dataclass
class RequirementResult:
    escrow_id: u256
    requirement_hash: str
    score: u256


# ---------------------------------------------------------------------------
# Intelligent Escrow
# ---------------------------------------------------------------------------

class IntelligentEscrow(gl.Contract):

    escrows: DynArray[Escrow]
    requirement_results: DynArray[RequirementResult]

    def __init__(self):
        pass

    # -----------------------------------------------------------------------
    # CREATE ESCROW
    # -----------------------------------------------------------------------

    @gl.public.write
    def create_escrow(
        self,
        seller: str,
        task: str,
        requirements: str,
        submission_url: str,
        amount: int
    ) -> int:

        buyer = str(gl.message.sender_address)

        require(len(seller.strip()) > 0, "seller is empty")
        require(len(task.strip()) > 0, "task is empty")
        require(len(requirements.strip()) > 0, "requirements are empty")
        require(len(submission_url.strip()) > 0, "submission URL is empty")
        require(amount > 0, "amount must be positive")

        escrow_id = len(self.escrows)

        self.escrows.append(
            Escrow(
                buyer=buyer,
                seller=seller.strip(),

                task=task.strip(),
                requirements=requirements.strip(),
                submission_url=submission_url.strip(),

                amount=u256(amount),

                status="AWAITING_SUBMISSION",
                score=u256(0),

                decision_hash=""
            )
        )

        return escrow_id

    # -----------------------------------------------------------------------
    # START REVIEW
    # -----------------------------------------------------------------------

    @gl.public.write
    def evaluate_submission(self, escrow_id: int) -> str:

        require(
            0 <= escrow_id < len(self.escrows),
            "escrow does not exist"
        )

        escrow = self.escrows[escrow_id]

        require(
            escrow.status in (
                "AWAITING_SUBMISSION",
                "SUBMITTED"
            ),
            "escrow cannot be evaluated"
        )

        task = escrow.task
        requirements = escrow.requirements
        submission_url = escrow.submission_url

        # -------------------------------------------------------------------
        # Leader evaluation
        # -------------------------------------------------------------------

        def leader_fn():

            page = gl.nondet.web.get(
                submission_url
            )

            submission = page.body.decode("utf-8")

            prompt = f"""
You are an independent escrow quality evaluator.

Your decision determines whether a seller completed a task.

ORIGINAL TASK:
{task}

REQUIREMENTS:
{requirements}

SUBMITTED WORK:
{submission}

Evaluate ONLY what can be established from the submitted work.

Do not invent facts.

For every requirement, determine whether it is:

PASS
PARTIAL
FAIL

Then calculate an overall score from 0 to 1000.

Decision rules:

800-1000:
RELEASE

500-799:
PARTIAL

0-499:
REFUND

Return ONLY JSON:

{{
    "decision": "RELEASE | PARTIAL | REFUND",
    "score": 0,
    "requirements": [
        {{
            "requirement": "requirement text",
            "status": "PASS | PARTIAL | FAIL",
            "score": 0
        }}
    ],
    "reason": "short explanation"
}}

The score must be an integer from 0 to 1000.
"""

            result = gl.nondet.exec_prompt(
                prompt,
                response_format="json"
            )

            require(
                isinstance(result, dict),
                "invalid evaluator response"
            )

            decision = str(
                result.get("decision", "")
            ).upper()

            require(
                decision in (
                    "RELEASE",
                    "PARTIAL",
                    "REFUND"
                ),
                "invalid decision"
            )

            score = int(
                result.get("score", -1)
            )

            require(
                0 <= score <= 1000,
                "invalid score"
            )

            requirements_result = result.get(
                "requirements",
                []
            )

            require(
                isinstance(requirements_result, list),
                "invalid requirements result"
            )

            # Recalculate decision from score.
            if score >= 800:
                expected = "RELEASE"
            elif score >= 500:
                expected = "PARTIAL"
            else:
                expected = "REFUND"

            require(
                decision == expected,
                "decision does not match score"
            )

            return {
                "decision": decision,
                "score": score,
                "requirements": requirements_result
            }

        # -------------------------------------------------------------------
        # Validator
        # -------------------------------------------------------------------

        def validator_fn(leader_result):

            if not isinstance(
                leader_result,
                gl.vm.Return
            ):
                return False

            leader = leader_result.calldata

            if not isinstance(leader, dict):
                return False

            # Validator independently evaluates the same submission.
            own = leader_fn()

            if not isinstance(own, dict):
                return False

            # Decision must agree exactly.
            if own["decision"] != leader["decision"]:
                return False

            # Scores can differ slightly between LLMs.
            if abs(
                int(own["score"])
                -
                int(leader["score"])
            ) > 100:
                return False

            # Make sure both results contain requirement evaluations.
            if not isinstance(
                own.get("requirements"),
                list
            ):
                return False

            if not isinstance(
                leader.get("requirements"),
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

        decision = result["decision"]
        score = int(result["score"])

        # -------------------------------------------------------------------
        # Store only after consensus.
        # -------------------------------------------------------------------

        decision_hash = hashlib.sha256(
            canonical({
                "escrow_id": escrow_id,
                "decision": decision,
                "score": score
            }).encode()
        ).hexdigest()

        self.escrows[escrow_id] = Escrow(
            buyer=escrow.buyer,
            seller=escrow.seller,

            task=escrow.task,
            requirements=escrow.requirements,
            submission_url=escrow.submission_url,

            amount=escrow.amount,

            status=decision,
            score=u256(score),

            decision_hash=decision_hash
        )

        return decision

    # -----------------------------------------------------------------------
    # GET ESCROW
    # -----------------------------------------------------------------------

    @gl.public.view
    def get_escrow(
        self,
        escrow_id: int
    ) -> str:

        require(
            0 <= escrow_id < len(self.escrows),
            "escrow does not exist"
        )

        e = self.escrows[escrow_id]

        return canonical({
            "escrow_id": escrow_id,

            "buyer": e.buyer,
            "seller": e.seller,

            "task": e.task,
            "requirements": e.requirements,
            "submission_url": e.submission_url,

            "amount": int(e.amount),

            "status": e.status,
            "score": int(e.score),

            "decision_hash": e.decision_hash
        })

    # -----------------------------------------------------------------------
    # CHECK STATUS
    # -----------------------------------------------------------------------

    @gl.public.view
    def status(
        self,
        escrow_id: int
    ) -> str:

        require(
            0 <= escrow_id < len(self.escrows),
            "escrow does not exist"
        )

        return self.escrows[escrow_id].status

    # -----------------------------------------------------------------------
    # COUNTS
    # -----------------------------------------------------------------------

    @gl.public.view
    def escrow_count(self) -> int:
        return len(self.escrows)

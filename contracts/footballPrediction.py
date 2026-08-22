
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
# Prediction record
# ---------------------------------------------------------------------------

@allow_storage
@dataclass
class Prediction:
    market_id: u256
    predictor: str
    choice: str


# ---------------------------------------------------------------------------
# Match record
# ---------------------------------------------------------------------------

@allow_storage
@dataclass
class Match:
    home_team: str
    away_team: str
    result_url: str

    status: str
    winner: str

    home_score: u256
    away_score: u256

    result_hash: str


# ---------------------------------------------------------------------------
# Football Prediction Market
# ---------------------------------------------------------------------------

class FootballPredictionMarket(gl.Contract):

    matches: DynArray[Match]
    predictions: DynArray[Prediction]

    def __init__(self):
        pass

    # -----------------------------------------------------------------------
    # CREATE MATCH
    # -----------------------------------------------------------------------

    @gl.public.write
    def create_match(
        self,
        home_team: str,
        away_team: str,
        result_url: str
    ) -> int:

        home = home_team.strip()
        away = away_team.strip()
        url = result_url.strip()

        require(len(home) > 0, "home team is empty")
        require(len(away) > 0, "away team is empty")
        require(home.lower() != away.lower(), "teams must be different")
        require(len(url) > 0, "result URL is empty")

        match_id = len(self.matches)

        self.matches.append(
            Match(
                home_team=home,
                away_team=away,
                result_url=url,

                status="OPEN",
                winner="UNRESOLVED",

                home_score=u256(0),
                away_score=u256(0),

                result_hash=""
            )
        )

        return match_id

    # -----------------------------------------------------------------------
    # PLACE PREDICTION
    # -----------------------------------------------------------------------

    @gl.public.write
    def predict(
        self,
        market_id: int,
        choice: str
    ) -> str:

        require(
            0 <= market_id < len(self.matches),
            "market does not exist"
        )

        market = self.matches[market_id]

        require(
            market.status == "OPEN",
            "market is not open"
        )

        prediction = choice.strip().upper()

        require(
            prediction in ("HOME", "AWAY", "DRAW"),
            "prediction must be HOME, AWAY, or DRAW"
        )

        # One prediction per address for each market.
        sender = str(gl.message.sender_address)

        for existing in self.predictions:

            if (
                int(existing.market_id) == market_id
                and existing.predictor == sender
            ):
                raise _Error("already predicted")

        self.predictions.append(
            Prediction(
                market_id=u256(market_id),
                predictor=sender,
                choice=prediction
            )
        )

        return prediction

    # -----------------------------------------------------------------------
    # RESOLVE MATCH
    #
    # This is where GenLayer's intelligent capability is used.
    # -----------------------------------------------------------------------

    @gl.public.write
    def resolve_match(self, market_id: int) -> str:

        require(
            0 <= market_id < len(self.matches),
            "market does not exist"
        )

        market = self.matches[market_id]

        require(
            market.status == "OPEN",
            "market already resolved"
        )

        home = market.home_team
        away = market.away_team
        url = market.result_url

        # -------------------------------------------------------------------
        # Leader fetches the external result and extracts ONLY stable fields.
        # -------------------------------------------------------------------

        def leader_fn():

            response = gl.nondet.web.get(url)

            page = response.body.decode("utf-8")

            prompt = f"""
You are a football match result verification agent.

You must determine the FINAL result of this football match from the
provided webpage.

HOME TEAM:
{home}

AWAY TEAM:
{away}

WEBPAGE:
{page}

IMPORTANT:

Only use information actually present in the webpage.

Do not predict the result.

Do not use historical knowledge.

Do not invent a score.

The match must be considered finished only if the webpage provides
a final score/result.

Return ONLY JSON:

{{
    "finished": true,
    "home_score": 0,
    "away_score": 0
}}

If the match has not finished or the result cannot be reliably determined:

{{
    "finished": false,
    "home_score": 0,
    "away_score": 0
}}
"""

            result = gl.nondet.exec_prompt(
                prompt,
                response_format="json"
            )

            require(
                isinstance(result, dict),
                "invalid result response"
            )

            finished = bool(result.get("finished", False))

            home_score = int(result.get("home_score", 0))
            away_score = int(result.get("away_score", 0))

            require(
                home_score >= 0,
                "invalid home score"
            )

            require(
                away_score >= 0,
                "invalid away score"
            )

            return {
                "finished": finished,
                "home_score": home_score,
                "away_score": away_score
            }

        # -------------------------------------------------------------------
        # Validators independently fetch the same page and verify the
        # important stable fields.
        # -------------------------------------------------------------------

        def validator_fn(leader_result):

            if not isinstance(leader_result, gl.vm.Return):
                return False

            leader = leader_result.calldata

            if not isinstance(leader, dict):
                return False

            own = leader_fn()

            if not isinstance(own, dict):
                return False

            # The match status must agree.
            if own["finished"] != leader["finished"]:
                return False

            # If unfinished, nothing else needs to match.
            if not own["finished"]:
                return True

            # Finished matches must have identical final scores.
            return (
                own["home_score"] == leader["home_score"]
                and
                own["away_score"] == leader["away_score"]
            )

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

        require(
            result["finished"],
            "match has not finished"
        )

        home_score = int(result["home_score"])
        away_score = int(result["away_score"])

        # -------------------------------------------------------------------
        # Determine winner deterministically AFTER consensus.
        # -------------------------------------------------------------------

        if home_score > away_score:
            winner = "HOME"

        elif away_score > home_score:
            winner = "AWAY"

        else:
            winner = "DRAW"

        result_hash = hashlib.sha256(
            canonical({
                "home_team": home,
                "away_team": away,
                "home_score": home_score,
                "away_score": away_score,
                "winner": winner
            }).encode()
        ).hexdigest()

        # -------------------------------------------------------------------
        # Store final result.
        # -------------------------------------------------------------------

        self.matches[market_id] = Match(
            home_team=market.home_team,
            away_team=market.away_team,
            result_url=market.result_url,

            status="RESOLVED",
            winner=winner,

            home_score=u256(home_score),
            away_score=u256(away_score),

            result_hash=result_hash
        )

        return winner

    # -----------------------------------------------------------------------
    # CHECK PREDICTION
    # -----------------------------------------------------------------------

    @gl.public.view
    def prediction_result(
        self,
        market_id: int,
        predictor: str
    ) -> str:

        require(
            0 <= market_id < len(self.matches),
            "market does not exist"
        )

        market = self.matches[market_id]

        for prediction in self.predictions:

            if (
                int(prediction.market_id) == market_id
                and prediction.predictor == predictor
            ):

                if market.status != "RESOLVED":
                    return canonical({
                        "prediction": prediction.choice,
                        "status": "PENDING"
                    })

                return canonical({
                    "prediction": prediction.choice,
                    "actual_result": market.winner,
                    "correct": prediction.choice == market.winner,
                    "status": "RESOLVED"
                })

        return canonical({
            "status": "NO_PREDICTION"
        })

    # -----------------------------------------------------------------------
    # GET MATCH
    # -----------------------------------------------------------------------

    @gl.public.view
    def get_match(self, market_id: int) -> str:

        require(
            0 <= market_id < len(self.matches),
            "market does not exist"
        )

        market = self.matches[market_id]

        return canonical({
            "market_id": market_id,
            "home_team": market.home_team,
            "away_team": market.away_team,
            "status": market.status,
            "winner": market.winner,
            "home_score": int(market.home_score),
            "away_score": int(market.away_score),
            "result_hash": market.result_hash
        })

    # -----------------------------------------------------------------------
    # COUNTS
    # -----------------------------------------------------------------------

    @gl.public.view
    def match_count(self) -> int:
        return len(self.matches)

    @gl.public.view
    def prediction_count(self) -> int:
        return len(self.predictions)

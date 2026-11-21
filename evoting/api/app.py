"""API FastAPI: rutas de administración y de urna (prototipo local, sin autenticación)."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, StrictInt

from evoting.protocol.authority import Authority
from evoting.protocol.ballot_box import BallotBox
from evoting.storage.db import Store


class CreateElection(BaseModel):
    question: str
    n_max: StrictInt


class IssueTokens(BaseModel):
    count: StrictInt


def create_app(db_path: str) -> FastAPI:
    store = Store(db_path)
    authority = Authority(store)
    box = BallotBox(store)
    app = FastAPI(title="Votación ElGamal (prototipo)")

    def _not_found(eid: str) -> HTTPException:
        return HTTPException(status_code=404, detail=f"La elección {eid} no existe")

    @app.exception_handler(ValueError)
    async def _value_error(_request: Request, exc: ValueError):
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(KeyError)
    async def _key_error(_request: Request, exc: KeyError):
        return JSONResponse(status_code=404,
                            content={"detail": f"La elección {exc.args[0]} no existe"})

    @app.post("/admin/elections")
    def create_election(body: CreateElection):
        return authority.create_election(body.question, body.n_max).to_dict()

    @app.post("/admin/elections/{eid}/tokens")
    def issue_tokens(eid: str, body: IssueTokens):
        return [t.to_dict() for t in authority.issue_tokens(eid, body.count)]

    @app.post("/admin/elections/{eid}/close")
    def close_election(eid: str):
        return authority.close(eid)

    @app.get("/admin/elections/{eid}/expediente")
    def get_expediente(eid: str):
        d = authority.get_expediente(eid)
        if d is None:
            raise _not_found(eid)
        return d

    @app.get("/urna/elections/{eid}/params")
    def get_params(eid: str):
        params = store.load_params(eid)
        if params is None:
            raise _not_found(eid)
        return params.to_dict()

    @app.get("/urna/elections/{eid}/status")
    def get_status(eid: str):
        if store.get_state(eid) is None:
            raise _not_found(eid)
        return box.status(eid)

    @app.post("/urna/ballots")
    async def submit_ballot(request: Request):
        try:
            raw = await request.json()
        except (ValueError, RecursionError):
            return JSONResponse(status_code=400, content={
                "accepted": False, "step": "FORMAT", "step_number": 0,
                "reason": "JSON inválido"})
        res = box.submit(raw)
        if res.accepted:
            return {"accepted": True, "ballot_hash": res.ballot_hash}
        return JSONResponse(status_code=400, content={
            "accepted": False, "step": res.step.name, "step_number": int(res.step),
            "reason": res.reason})

    return app

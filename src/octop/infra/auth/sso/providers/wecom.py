"""WeCom (企业微信) CorpApp web login adapter for dashboard SSO."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import httpx
import jwt

from octop.infra.auth.sso.crypto import decrypt_secret
from octop.infra.auth.sso.public_base import oauth_callback_path
from octop.infra.db.repos.sso import SsoLoginStateRow, SsoProviderRow

if TYPE_CHECKING:
    from octop.infra.auth.sso.service import SsoService

# Browser / QR web login (path 98152), not in-WeCom oauth2 authorize.
_AUTHORIZE = "https://login.work.weixin.qq.com/wwlogin/sso/login"
_API = "https://qyapi.weixin.qq.com"
_MAX_DEPT_DEPTH = 20

logger = logging.getLogger(__name__)


def wecom_agent_id(row: SsoProviderRow) -> str:
    raw = row.extra.get("agent_id")
    if isinstance(raw, int):
        return str(raw)
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return ""


class WeComAdapter:
    kind = "wecom"
    callback_path = oauth_callback_path()
    default_scopes = ""

    def __init__(self, service: SsoService) -> None:
        self._service = service

    def is_configured(self, row: SsoProviderRow) -> bool:
        return bool(
            row.client_id.strip() and row.client_secret_enc is not None and wecom_agent_id(row)
        )

    def authorize_url(
        self,
        *,
        row: SsoProviderRow,
        state: str,
        nonce: str,
        code_challenge: str,
        redirect_uri: str,
    ) -> str:
        del nonce, code_challenge
        agent_id = wecom_agent_id(row)
        if not agent_id:
            raise ValueError("WeCom Agent ID is not configured")
        params = {
            "login_type": "CorpApp",
            "appid": row.client_id,
            "agentid": agent_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }
        return f"{_AUTHORIZE}?{urlencode(params)}"

    def complete_login(
        self,
        code: str,
        *,
        row: SsoProviderRow,
        login_state: SsoLoginStateRow,
        redirect_uri: str,
    ) -> tuple[str, dict[str, Any]]:
        del redirect_uri, login_state
        if row.client_secret_enc is None:
            raise ValueError("WeCom app secret is not configured")
        secret = decrypt_secret(self._service._services.secret_repo, row.client_secret_enc)
        with self._service._http_client() as client:
            access_token = self._access_token(client, corpid=row.client_id, secret=secret)
            user_response = client.get(
                f"{_API}/cgi-bin/auth/getuserinfo",
                params={"access_token": access_token, "code": code},
            )
            try:
                user_response.raise_for_status()
                identity = user_response.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise ValueError(str(exc)) from exc
            if not isinstance(identity, dict):
                raise ValueError("WeCom user info is not an object")
            errcode = identity.get("errcode", 0)
            if errcode not in (0, "0", None):
                errmsg = identity.get("errmsg")
                detail = errmsg if isinstance(errmsg, str) and errmsg else f"WeCom error {errcode}"
                raise ValueError(detail)
            userid = identity.get("userid")
            if not isinstance(userid, str) or not userid:
                raise jwt.InvalidTokenError("WeCom user info has no userid")
            claims = self._member_claims(client, access_token=access_token, userid=userid)
            user_ticket = identity.get("user_ticket")
            if isinstance(user_ticket, str) and user_ticket:
                sensitive = self._sensitive_claims(
                    client, access_token=access_token, user_ticket=user_ticket
                )
                detail = sensitive.pop("raw_user_detail", None)
                claims.update(sensitive)
                if detail and isinstance(claims.get("sso_profile"), dict):
                    claims["sso_profile"]["raw_user_detail"] = detail
        return userid, claims

    def test_connection(self, row: SsoProviderRow) -> dict[str, bool | str]:
        if row.client_secret_enc is None:
            return {"ok": False, "detail": "WeCom app secret is not configured"}
        if not wecom_agent_id(row):
            return {"ok": False, "detail": "WeCom Agent ID is not configured"}
        secret = decrypt_secret(self._service._services.secret_repo, row.client_secret_enc)
        try:
            with self._service._http_client() as client:
                self._access_token(client, corpid=row.client_id, secret=secret)
        except (httpx.HTTPError, ValueError) as exc:
            return {"ok": False, "detail": str(exc)}
        return {"ok": True, "detail": "WeCom app credentials are valid"}

    @staticmethod
    def _access_token(client: httpx.Client, *, corpid: str, secret: str) -> str:
        response = client.get(
            f"{_API}/cgi-bin/gettoken",
            params={"corpid": corpid, "corpsecret": secret},
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("WeCom token response is not an object")
        errcode = payload.get("errcode", 0)
        if errcode not in (0, "0", None):
            errmsg = payload.get("errmsg")
            detail = errmsg if isinstance(errmsg, str) and errmsg else f"WeCom error {errcode}"
            raise ValueError(detail)
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise ValueError("WeCom token response has no access_token")
        return token

    @classmethod
    def _member_claims(
        cls, client: httpx.Client, *, access_token: str, userid: str
    ) -> dict[str, Any]:
        response = client.get(
            f"{_API}/cgi-bin/user/get",
            params={"access_token": access_token, "userid": userid},
        )
        response.raise_for_status()
        payload = response.json()
        profile: dict[str, Any] = {"userid": userid}
        if not isinstance(payload, dict) or payload.get("errcode", 0) not in (0, "0", None):
            if isinstance(payload, dict):
                logger.warning(
                    "WeCom user/get failed for %s: errcode=%s errmsg=%s",
                    userid,
                    payload.get("errcode"),
                    payload.get("errmsg"),
                )
            return {"sso_profile": profile}
        claims: dict[str, Any] = {}
        name = payload.get("name")
        email = payload.get("biz_mail") or payload.get("email")
        if isinstance(name, str) and name.strip():
            claims["name"] = name.strip()
            profile["name"] = name.strip()
        if isinstance(email, str) and email.strip():
            claims["email"] = email.strip()
        position = payload.get("position")
        if isinstance(position, str) and position.strip():
            profile["position"] = position.strip()

        dept_ids = [d for d in payload.get("department") or [] if isinstance(d, int)]
        main_id = payload.get("main_department")
        if not isinstance(main_id, int):
            main_id = dept_ids[0] if dept_ids else None

        # Company = the member's external (business-card) company name.
        external = payload.get("external_profile")
        corp = external.get("external_corp_name") if isinstance(external, dict) else None
        profile["company"] = corp.strip() if isinstance(corp, str) and corp.strip() else None

        # Every department the member belongs to, each with its full path from the root,
        # so any level (company / business unit / team) can be picked later.
        depts = _DeptLookup(client, access_token)
        departments = [depts.describe(d) for d in dept_ids]
        profile["departments"] = departments
        profile["main_department"] = next((d for d in departments if d["id"] == main_id), None)

        # Keep the untouched user/get response so no field is ever lost.
        profile["raw_user"] = {k: v for k, v in payload.items() if k not in ("errcode", "errmsg")}
        claims["sso_profile"] = profile
        return claims

    @staticmethod
    def _sensitive_claims(
        client: httpx.Client, *, access_token: str, user_ticket: str
    ) -> dict[str, Any]:
        response = client.post(
            f"{_API}/cgi-bin/auth/getuserdetail",
            params={"access_token": access_token},
            json={"user_ticket": user_ticket},
        )
        try:
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError):
            return {}
        if not isinstance(payload, dict) or payload.get("errcode", 0) not in (0, "0", None):
            return {}
        claims: dict[str, Any] = {}
        email = payload.get("biz_mail") or payload.get("email")
        if isinstance(email, str) and email.strip():
            claims["email"] = email.strip()
        claims["raw_user_detail"] = {
            k: v for k, v in payload.items() if k not in ("errcode", "errmsg")
        }
        return claims


class _DeptLookup:
    """Per-login cache over ``cgi-bin/department/get`` (best effort, never raises)."""

    def __init__(self, client: httpx.Client, access_token: str) -> None:
        self._client = client
        self._token = access_token
        self._cache: dict[int, dict[str, Any] | None] = {}

    def get(self, dept_id: int) -> dict[str, Any] | None:
        if dept_id in self._cache:
            return self._cache[dept_id]
        dept: dict[str, Any] | None = None
        try:
            response = self._client.get(
                f"{_API}/cgi-bin/department/get",
                params={"access_token": self._token, "id": dept_id},
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError):
            payload = None
        if isinstance(payload, dict) and payload.get("errcode", 0) in (0, "0", None):
            raw = payload.get("department")
            dept = raw if isinstance(raw, dict) else None
        elif isinstance(payload, dict):
            logger.warning(
                "WeCom department/get failed for %s: errcode=%s errmsg=%s",
                dept_id,
                payload.get("errcode"),
                payload.get("errmsg"),
            )
        self._cache[dept_id] = dept
        return dept

    def name(self, dept_id: int | None) -> str | None:
        if dept_id is None:
            return None
        dept = self.get(dept_id)
        name = dept.get("name") if dept else None
        return name.strip() if isinstance(name, str) and name.strip() else None

    def describe(self, dept_id: int) -> dict[str, Any]:
        """``{id, name, parentid, path}`` where ``path`` runs root → this department.

        An ancestor whose lookup fails is kept with ``name`` None and the walk stops
        there, so a partial path starts at the first unreadable ancestor.
        """
        path: list[dict[str, Any]] = []
        seen: set[int] = set()
        current: int | None = dept_id
        while current is not None and current not in seen and len(seen) < _MAX_DEPT_DEPTH:
            seen.add(current)
            dept = self.get(current)
            path.append({"id": current, "name": self.name(current)})
            parent = dept.get("parentid") if dept else None
            current = parent if isinstance(parent, int) and parent > 0 else None
        path.reverse()
        dept = self.get(dept_id)
        parent = dept.get("parentid") if dept else None
        return {
            "id": dept_id,
            "name": self.name(dept_id),
            "parentid": parent if isinstance(parent, int) else None,
            "path": path,
        }

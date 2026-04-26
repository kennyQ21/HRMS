import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_SECRET = "super_secret_key"
_ALGORITHM = "HS256"
_REQUIRED_ORG = "Patronus1"

_bearer = HTTPBearer(auto_error=False)


def verify_token(credentials: HTTPAuthorizationCredentials = Security(_bearer)) -> dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="Authorization header missing")

    try:
        payload = jwt.decode(credentials.credentials, _SECRET, algorithms=[_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.get("org_name") != _REQUIRED_ORG:
        raise HTTPException(status_code=403, detail="Auth issue: org_name must be Patronus1")

    return payload

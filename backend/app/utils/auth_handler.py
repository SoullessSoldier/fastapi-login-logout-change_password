import time
from typing import Dict

from jose import jwt

from .utils import JWT_SECRET_KEY, ALGORITHM


def token_response(token: str):
    return {
        "access_token": token
    }


def sign_jwt(user_id: str) -> Dict[str, str]:
    payload = {
        "user_id": user_id,
        "expires": time.time() + 900
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=ALGORITHM)

    return token_response(token)


def decode_jwt(token: str) -> dict:
    try:
        decoded_token = jwt.decode(token, JWT_SECRET_KEY,
                                   algorithms=[ALGORITHM])
        return decoded_token if decoded_token["expires"] >= time.time()\
            else None
    except:
        return {}

import jwt
from datetime import datetime, timedelta, timezone


SECRET_KEY = "my-secret-key"
ALGORITHM = "HS256"


def create_access_token(data: dict, expires_minutes: int) -> str:
    payload = data.copy()

    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)

    payload["exp"] = expire

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return token


def decode_access_token(token: str) -> dict:
    payload = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM]
    )

    return payload


token = create_access_token(
    data={
        "sub": "student01@gmail.com",
        "user_id": 1,
        "role": "student"
    },
    expires_minutes=30
)

print(token)
print(decode_access_token(token))
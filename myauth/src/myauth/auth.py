from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta
from fastapi import HTTPException, status
import uuid

SECRET = "c6b575ec054842316d34e854044b7be013677a8c7ec332049be2a89a8fb12142"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_TIME = 15
ISSUER = "fastapi-auth-server"
AUDIENCE = "fastapi-clients"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(plain_password):
    return pwd_context.hash(plain_password)

def create_token(data:dict, expiry_time: timedelta = None):
    to_encode = data.copy()
    if expiry_time:
        token_expire = datetime.utcnow() + expiry_time
    else:
        token_expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_TIME)

    now = datetime.utcnow()
    jti = uuid.uuid4().hex
    claims_dict = {
        "iss": ISSUER,           # Issuer
        "sub": str(data["sub"]), # Subject (user ID)
        "aud": AUDIENCE,         # Audience
        "exp": token_expire,           # Expiration Time
        "nbf": now,              # Not Before
        "iat": now,              # Issued At
        "jti": jti               # JWT ID
    }
    to_encode.update(claims_dict)
    token = jwt.encode(claims=to_encode, key=SECRET, algorithm=ALGORITHM)
    return token

def decode_token(token):   
    try:
        payload = jwt.decode(token=token, key=SECRET, algorithms=ALGORITHM, audience=AUDIENCE, issuer=ISSUER)
        print(payload)
        return payload
    
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token verification failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
from src.myauth.models import User
from src.myauth.database import Base, engine, SessionLocal
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from src.myauth.schema import UserProfile
from src.myauth.models import User
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from src.myauth.auth import decode_token, create_token, hash_password, verify_password

app = FastAPI()

# Base.metadata.create_all(bind=engine)

security = HTTPBearer()

def get_db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close

def get_current_user(credentials : HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Credentials not found.")
    token = credentials.credentials
    payload = decode_token(token=token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Not valid credentials.")
    return username


@app.get("/")
def get_status():
    return {"msg":"OK"}

@app.post("/register")
def register_user(username:str, password:str, email:str, db:Session = Depends(get_db)):
    hashed_password = hash_password(password)
    user = User(username = username, hashed_password = hashed_password, email = email)
    db.add(user)
    db.commit()
    return {"msg":"user registered successfully !!"}

@app.post("/login")
def login_user(username:str, password:str, db:Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user.username:
        raise HTTPException(status_code=401, detail="user not found")
    if not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="incorrect password")
    access_token = create_token({"sub":user.username})
    return {"msg":"login successful", "access_token":access_token}

@app.get("/profile", response_model=UserProfile)
def get_profile(username : str = Depends(get_current_user), db:Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if user:
        return user
    else:
        raise HTTPException(status_code=400, detail="details not found.")
    


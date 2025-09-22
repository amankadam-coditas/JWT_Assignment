from pydantic import BaseModel

class UserProfile(BaseModel):
    id:int
    username:str
    email:str
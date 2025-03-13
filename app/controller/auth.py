from fastapi import APIRouter, Depends, HTTPException,Response,status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import timedelta
import jwt
from app.database import get_db
from jwt import PyJWTError
from app.model.token import Token
from app.service.auth import *
from app.repository.users import *
from starlette.config import Config

router = APIRouter()
config = Config('.env')

# OAuth2PasswordBearer: 클라이언트로부터 토큰을 받아오는 의존성
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    로그인 엔드포인트:
    - 클라이언트는 username과 password를 전송
    - 인증 성공 시 JWT 토큰을 반환
    """

    #유저 객체 받기
    user = authenticate_user(db,form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    #토큰 받기 및 토큰 반환
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}



@router.post("/register")
async def register(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    회원가입 엔드포인트:
    - 클라이언트는 username과 password를 전송
    - 사용자 생성 성공 시 사용자 정보 반환  
    """
    user = get_user_by_username(db,form_data.username)
    if user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    user = register_user(db,form_data.username, form_data.password)

    return Response(status_code=status.HTTP_200_OK)

@router.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    JWT 토큰을 통해 현재 로그인한 사용자 정보를 조회하는 엔드포인트.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = get_user_by_username(username)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    
    return {"username": user["username"]}

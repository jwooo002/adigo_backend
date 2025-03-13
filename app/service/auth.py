from datetime import datetime, timedelta, timezone;
from typing import Optional
import jwt
from passlib.context import CryptContext
from app.repository.users import *
from starlette.config import Config

# JWT 관련 설정 (실제 서비스에서는 SECRET_KEY를 안전하게 관리하세요)
config = Config('.env')
SECRET_KEY = config('SECRET_KEY')
ALGORITHM = "HS256"

# 비밀번호 암호화 및 검증용 컨텍스트
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    평문 비밀번호와 해시된 비밀번호 비교
    """
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(db: Session,username: str, password: str):
    """
    사용자 인증: 사용자 존재 여부와 비밀번호 일치 여부 확인
    """
    
    #유저가 존재 하는지 획인
    user = get_user_by_username(db,username)
    if not user:
        return None
    #유저가 존재 하지 않으면 None 반환


    #비밀번호 일치 여부 확인
    if not verify_password(password, user.hashed_password):
        return None
    return user

def create_access_token(data: dict):
    """
    JWT 토큰 생성: payload에 사용자 정보를 담고 만료 시간 설정
    """ 
    to_encode = data.copy()

    #만료시간 설정
    expire = datetime.now(timezone.utc) + timedelta(int(config('ACCESS_TOKEN_EXPIRE_MINUTES')))
    to_encode.update({"exp": expire})

    #토큰 암호화 및 반환
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def register_user(db: Session, username: str, password: str):
    """
    사용자 등록: 사용자 정보를 데이터베이스에 저장
    """

    #비밀번호 암호화
    hashed_password = pwd_context.hash(password)


    user = register_user_into_database(db, username, hashed_password)
    return user

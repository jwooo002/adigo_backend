from sqlalchemy.orm import Session
from app.model.user_orm import User



def get_user_by_username(db: Session, username: str):
    """
    주어진 데이터베이스 세션(db)과 username을 이용해 사용자 정보를 조회합니다.
    """
    return db.query(User).filter(User.username == username).first()

def register_user_into_database(db: Session, username: str, hashed_password: str):
    """
    주어진 데이터베이스 세션(db)과 username, password를 이용해 사용자를 생성합니다.
    """
    user = User(username=username, hashed_password=hashed_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

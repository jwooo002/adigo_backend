from fastapi import FastAPI
from sqlalchemy.orm import Session
from app.controller.auth import router as auth_router
from app.database import engine, Base


Base.metadata.create_all(bind=engine)

app = FastAPI()


# 컨트롤러 라우터 등록
app.include_router(auth_router)

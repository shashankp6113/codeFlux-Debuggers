from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from models import Base
from database import engine, get_db

app=FastAPI()

Base.metadata.create_all(bind=engine)

@app.get("/")
def root():
    return {"message":"MailForensics AI Backend is running"}

@app.get("/db-test")
def db_test(db: Session=Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"message":"Database connection successful"}
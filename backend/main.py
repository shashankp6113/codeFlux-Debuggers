from fastapi import FastAPI

app=FastAPI()

@app.get("/")
def root():
    return {"message":"MailForensics AI Backend is running"}
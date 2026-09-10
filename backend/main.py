from fastapi import FastAPI
import psycopg

app=FastAPI()

@app.get("/")
def root():
    return {"message":"MailForensics AI Backend is running"}

@app.get("/db-test")
def db_test():
    conn=psycopg.connect(
        host="database",
        dbname="mailforensics",
        user="mailforensics",
        password="mailforensics"
    )
    conn.close()
    return {"message":"Database connection successful"}
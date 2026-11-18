@app.get("/api/users")
def list_users(auth=Depends(get_current_user)):
    return []

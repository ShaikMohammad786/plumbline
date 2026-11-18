@app.post("/account/delete")
def delete_account(csrf=VerifyCsrfToken()):
    pass

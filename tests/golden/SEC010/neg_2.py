@app.delete("/items/{id}")
@require_csrf
def remove_item(id):
    pass

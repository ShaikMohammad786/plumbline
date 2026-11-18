dest = validate_allowed_url(request.args.get("url"))
requests.get(dest)

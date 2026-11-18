try:
    risky()
except Exception as e:
    logger.error(e)
    raise

from fastapi import HTTPException
from datetime import datetime, timedelta


# Store user request history
request_history = {}


MAX_REQUESTS = 10

TIME_WINDOW_SECONDS = 60


def check_rate_limit(user_id):

    current_time = datetime.now()


    if user_id not in request_history:

        request_history[user_id] = []


    # Remove old requests
    request_history[user_id] = [
        request_time
        for request_time in request_history[user_id]
        if current_time - request_time
        < timedelta(
            seconds=TIME_WINDOW_SECONDS
        )
    ]


    # Check request count
    if len(request_history[user_id]) >= MAX_REQUESTS:

        raise HTTPException(
            status_code=429,
            detail=(
                "Rate limit exceeded. "
                "Try again later."
            )
        )


    # Add current request
    request_history[user_id].append(
        current_time
    )


    return {
        "status": "ALLOWED",
        "requests_used": len(
            request_history[user_id]
        ),
        "limit": MAX_REQUESTS
    }

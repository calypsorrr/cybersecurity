from cybercheck.config import ENGAGEMENT_TOKEN

def verify_token(token: str) -> bool:
    if not ENGAGEMENT_TOKEN:
        return False
    return token.strip() == ENGAGEMENT_TOKEN

def require_active_session(request_token: str) -> bool:
    return verify_token(request_token)

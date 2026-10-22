import json

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from core.http import client_ip
from oauth.server import authorization_server_metadata, server
from services import audit, throttle
from services.signing import published_jwks


@require_GET
def jwks(request: HttpRequest) -> JsonResponse:
    response = JsonResponse(published_jwks())
    response["Cache-Control"] = "public, max-age=600"
    return response


@require_GET
def authorization_server_metadata_view(request: HttpRequest) -> JsonResponse:
    response = JsonResponse(authorization_server_metadata())
    response["Cache-Control"] = "public, max-age=3600"
    return response


@csrf_exempt
@require_POST
def register(request: HttpRequest) -> HttpResponse:
    """Dynamic Client Registration (RFC 7591). Every request counts toward the per-IP limit."""
    ip = client_ip(request)
    blocked = throttle.check("register", f"ip:{ip}")
    if not blocked.allowed:
        limited = JsonResponse({"error": "too_many_requests"}, status=429)
        limited["Retry-After"] = str(blocked.retry_after)
        return limited
    throttle.hit("register", f"ip:{ip}")
    response: HttpResponse = server.create_endpoint_response("client_registration", request)
    if response.status_code == 201:
        client_id = str(json.loads(response.content)["client_id"])
        audit.record(audit.CLIENT_REGISTERED, client_id=client_id, ip=ip, detail={"via": "dcr"})
    response["Cache-Control"] = "no-store"
    return response

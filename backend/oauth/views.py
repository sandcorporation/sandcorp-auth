from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_GET

from services.signing import published_jwks


@require_GET
def jwks(request: HttpRequest) -> JsonResponse:
    response = JsonResponse(published_jwks())
    response["Cache-Control"] = "public, max-age=600"
    return response

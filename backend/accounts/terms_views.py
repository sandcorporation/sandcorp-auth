"""The terms screen (#37): a member agrees to the current versions of the required documents
and confirms being 14 or older before it may get tokens. `/authorize` and the end of a social
login send a member here with `next`; the minimal template is styled later (#38)."""

from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods

from accounts.models import TermsDocument
from accounts.session import safe_next
from core.http import client_ip
from services.terms import (
    AgeNotConfirmed,
    TermsNotAccepted,
    TermsUnavailable,
    agree_to_terms,
    current_documents,
    needs_terms,
)

TEMPLATE = "accounts/terms.html"
AGE_MISSING = "만 14세 이상인지 확인해 주세요."
NOT_ALL = "필수 약관에 모두 동의해 주세요. 내용이 바뀌었다면 새 버전을 확인해 주세요."


def _document_ids(values: list[str]) -> set[int]:
    return {int(value) for value in values if value.isdecimal()}


@login_required
@require_http_methods(["GET", "POST"])
def terms(request: HttpRequest) -> HttpResponse:
    user = request.user
    assert isinstance(user, User)  # login_required
    source = request.POST if request.method == "POST" else request.GET
    next_url = safe_next(request, source.get("next")) or ""
    if not needs_terms(user):  # the owner, or a member who agreed already
        return redirect(next_url or "accounts:home")
    documents = current_documents()
    context = {"documents": documents, "next": next_url, "error": ""}
    if len(documents) < len(TermsDocument.Kind):
        return render(request, TEMPLATE, {**context, "unavailable": True}, status=503)
    if request.method == "GET":
        return render(request, TEMPLATE, context)
    try:
        agree_to_terms(
            user,
            document_ids=_document_ids(request.POST.getlist("document")),
            age_confirmed=request.POST.get("age_14") == "on",
            ip=client_ip(request),
        )
    except AgeNotConfirmed:
        return render(request, TEMPLATE, {**context, "error": AGE_MISSING}, status=400)
    except TermsNotAccepted:
        return render(request, TEMPLATE, {**context, "error": NOT_ALL}, status=400)
    except TermsUnavailable:
        return render(request, TEMPLATE, {**context, "unavailable": True}, status=503)
    return redirect(next_url or "accounts:home")

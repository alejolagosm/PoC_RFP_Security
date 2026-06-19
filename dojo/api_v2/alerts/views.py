import logging
from rest_framework import status
from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.db import transaction, IntegrityError
from dojo.models import Alerts
from dojo.api_v2.alerts.serializers import AlertsSerializers
from dojo.api_v2.views import DojoModelViewSet
from dojo.api_v2.utils import http_response
from dojo.authorization.roles_permissions import Permissions
from django_filters.rest_framework import DjangoFilterBackend
from dojo.api_v2.api_error import ApiError
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
    OpenApiTypes,
)
from dojo.api_v2 import (
    permissions,
    prefetch,
    serializers,
)
logger = logging.getLogger(__name__)


class ServiceAccount:
    is_authenticated = True
    is_active = True
    is_staff = False
    is_superuser = False
    id = 0
    pk = 0
    username = "service"

    def __str__(self):
        return self.username


class TokenHeaderAuthentication(BaseAuthentication):

    def authenticate(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if auth_header.startswith("Token "):
            return (ServiceAccount(), auth_header.split(" ", 1)[1])
        return None

    def authenticate_header(self, request):
        return 'Token'


@extend_schema_view(
    list=extend_schema(
        responses={status.HTTP_200_OK: AlertsSerializers(many=True)},
    ),
    create=extend_schema(
        request=AlertsSerializers,
        responses={status.HTTP_201_CREATED: AlertsSerializers},
    ),
)
class AlertViewSet(
    prefetch.PrefetchListMixin,
    prefetch.PrefetchRetrieveMixin,
    DojoModelViewSet
):
    queryset = Alerts.objects.all()
    authentication_classes = [TokenHeaderAuthentication]
    permission_classes = [AllowAny]
    serializer_class = AlertsSerializers
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "source",
        "created"]

    def get_queryset(self):
        user_id_param = self.request.query_params.get("user_id")
        if user_id_param:
            return Alerts.objects.filter(user_id=user_id_param)
        if self.request.query_params.get("scope") == "global":
            return Alerts.objects.all()
        if hasattr(self.request.user, 'id') and self.request.user.id:
            return Alerts.objects.filter(user_id=self.request.user.id)
        return Alerts.objects.none()

    def list(self, request, *args, **kwargs):
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth_header.startswith("Token "):
            return Response(
                {"detail": "Authentication credentials were not provided."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            alerts_qr = self.get_queryset()
            page = self.paginate_queryset(alerts_qr)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)
            serializer = self.get_serializer(alerts_qr, many=True)
            return http_response.ok(data=serializer.data)

        except Exception as e:
            logger.error(str(e))
            raise ApiError.internal_server_error(detail=str(e))

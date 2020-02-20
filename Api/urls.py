from rest_framework import routers
from django.urls import path, include, re_path
from rest_framework.authtoken.views import obtain_auth_token
from django.conf import settings
import logging
from Api import views

ACCOUNTING_URL = getattr(settings, "ACCOUNTING_URL")
ACCOUNTING_API_IGNORE = getattr(settings, "ACCOUNTING_API_IGNORE")
ACCOUNTING_API_PREFIX = getattr(settings, "ACCOUNTING_API_PREFIX")

logger = logging.getLogger(__name__)

router = routers.DefaultRouter()
router.register(r'validation', views.ValidationView, basename='Validation')
router.register(r'config/manage', views.ConfigurationViewSet, basename='Config Manage')
router.register(r'config/value', views.ConfigurationValueViewSet, basename='Config Value')

urlpatterns = [
    path('api/', include(router.urls)),
    path('api-token-auth/', obtain_auth_token, name='api_token_auth'),
    re_path('api/(?P<url>.*)/$', views.DefaultView.as_view(), name='default'),
]

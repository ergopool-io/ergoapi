from rest_framework import routers
from django.urls import path, include
from rest_framework.authtoken.views import obtain_auth_token
from django.conf import settings
from urllib.parse import urljoin
import requests
import logging
from Api import views

ACCOUNTING_URL = getattr(settings, "ACCOUNTING_URL")
ACCOUNTING_API_IGNORE = getattr(settings, "ACCOUNTING_API_IGNORE")
ACCOUNTING_API_PREFIX = getattr(settings, "ACCOUNTING_API_PREFIX")

logger = logging.getLogger(__name__)

router = routers.DefaultRouter()
router.register(r'share', views.ShareView, basename='Share')
router.register(r'header', views.HeaderView, basename='Header')
router.register(r'transaction', views.TransactionView, basename='Transaction')
router.register(r'config/manage', views.ConfigurationViewSet, basename='Config Manage')
router.register(r'config/value', views.ConfigurationValueViewSet, basename='Config Value')

# Add accounting service APIs
try:
    # Get APIs accounting service
    response = requests.get(ACCOUNTING_URL + '.json').json()
    # Accounting apis that should remove in this service
    for url in response:
        if url in ACCOUNTING_API_IGNORE:
            continue
        response = requests.options(urljoin(ACCOUNTING_URL, url))
        # Build a class and add functions for methods according to allowed method this url
        view = views.builder_viewset(response.headers['Allow'], response.json().get('actions'))
        router.register(r'%s/%s' % (ACCOUNTING_API_PREFIX, url), view, basename=url)
except requests.exceptions.RequestException as e:
    logger.error("Can not resolve response from Accounting service.")
    logger.error(e)


urlpatterns = [
    path('api/', include(router.urls)),
    path('api-token-auth/', obtain_auth_token, name='api_token_auth'),
    path('', views.AccountView.as_view(), name='account'),
    path('<str:public_key>/', views.AccountView.as_view(), name='account'),
]

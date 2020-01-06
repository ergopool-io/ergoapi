from rest_framework import routers
from django.urls import path, include
from rest_framework.authtoken.views import obtain_auth_token
from ErgoApi.settings import ACCOUNTING_URL, ACCOUNTING_API_IGNORE, PREFIX_ACCOUNTING_API
from . import views
import requests
import logging

logger = logging.getLogger(__name__)

router = routers.DefaultRouter()
router.register(r'share', views.ShareView, basename='Share')
router.register(r'header', views.HeaderView, basename='Header')
router.register(r'transaction', views.TransactionView, basename='Transaction')
router.register(r'config/manage', views.ConfigurationViewSet, basename='Config Manage')
router.register(r'config/value', views.ConfigurationValueViewSet, basename='Config Value')
router.register(r'dashboard', views.DashboardView, basename='Dashboard')

# Add accounting service APIs
try:
    response = requests.get(ACCOUNTING_URL + '.json').json()
    for url in response:
        if url in ACCOUNTING_API_IGNORE:
            continue
        router.register(r'{0}/{1}'.format(PREFIX_ACCOUNTING_API, url), views.ProxyView, basename=url)
except requests.exceptions.RequestException as e:
    logger.error("Can not resolve response from Accounting service.")
    logger.error(e)


urlpatterns = [
    path('api/', include(router.urls)),
    path('api-token-auth/', obtain_auth_token, name='api_token_auth'),
    path('', views.AccountView.as_view(), name='account'),
    path('<str:public_key>/', views.AccountView.as_view(), name='account'),
]

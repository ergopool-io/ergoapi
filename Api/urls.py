from rest_framework import routers
from django.urls import path, include
from rest_framework.authtoken.views import obtain_auth_token

from . import views


router = routers.DefaultRouter()
router.register(r'share', views.ShareView, basename='Share')
router.register(r'header', views.HeaderView, basename='Header')
router.register(r'transaction', views.TransactionView, basename='Transaction')
router.register(r'config/manage', views.ConfigurationViewSet, basename='Config Manage')
router.register(r'config/value', views.ConfigurationValueViewSet, basename='Config Value')
router.register(r'dashboard', views.DashboardView, basename='Dashboard')


urlpatterns = [
    path('api/', include(router.urls)),
    path('api-token-auth/', obtain_auth_token, name='api_token_auth'),
    path('', views.AccountView.as_view(), name='account'),
    path('<str:public_key>/', views.AccountView.as_view(), name='account'),
]

from rest_framework import routers
from django.urls import path, include

from . import views


router = routers.DefaultRouter()
router.register(r'share', views.ShareView, basename='Share')
router.register(r'header', views.HeaderView, basename='Header')


urlpatterns = [
    path('api/', include(router.urls)),
    path('', views.AccountView.as_view(), name='account'),
    path('<str:public_key>/', views.AccountView.as_view(), name='account'),
]

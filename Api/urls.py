from django.urls import path, include
from rest_framework import routers

from Api.views import HelloWorldViewset

router = routers.DefaultRouter()
router.register('hello', HelloWorldViewset, basename='')

urlpatterns = [
    path('', include(router.urls))
]

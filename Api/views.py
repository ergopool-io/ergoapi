from rest_framework import viewsets
from rest_framework.response import Response


class HelloWorldViewset(viewsets.ViewSet):
    """
    A simple ViewSet for test system
    """
    def list(self, request):
        return Response({"answoer": "hello world!!!!"})

from Api.utils.general import LazyConfiguration


class ConfigurationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.configs = LazyConfiguration()

        response = self.get_response(request)
        return response

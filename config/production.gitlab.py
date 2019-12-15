# # Database
# # https://docs.djangoproject.com/en/2.2/ref/settings/#databases
import os

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'ergo',
        'USER': 'ergo',
        'PASSWORD': 'ergo',
        'HOST': 'postgres',  # same as the docker-compose service
        'PORT': 5432,
    }
}
# Allowed Hosts
ALLOWED_HOSTS = []

# Access url for accounting system
ACCOUNTING_URL = "http://accounting"


# Address Node (ex: "http://127.0.0.1:9053/")
NODE_ADDRESS = "http://node:6052/"

# Secret Key of Node(apiKey) (ex: "623f4e8e440007f45020afabbf56d8ba43144778757ea88497c794ad529a0433")
API_KEY = 'secret'

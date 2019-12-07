# # Database
# # https://docs.djangoproject.com/en/2.2/ref/settings/#databases
import os

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'db_api',
        'USER': 'admin',
        'PASSWORD': 'admin',
        'HOST': 'db',  # same as the docker-compose service
        'PORT': 5432,
    }
}
# Allowed Hosts
ALLOWED_HOSTS = [os.environ.get('HOST')]

# Access url for accounting system
ACCOUNTING_URL = "http://" + os.environ.get("ACCOUNTING")


# Difficulty of pool (pb) (ex: 799144731656113400000000000000000000000000000000000000000000000)
POOL_DIFFICULTY = "7799144731656113400000000000000000000000000000000000000000000000"

# Address Node (ex: "http://127.0.0.1:9053/")
NODE_ADDRESS = os.environ.get("NODE")

# Secret Key of Node(apiKey) (ex: "623f4e8e440007f45020afabbf56d8ba43144778757ea88497c794ad529a0433")
API_KEY = os.environ.get("SECRET")

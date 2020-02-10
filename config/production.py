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
ACCOUNTING_IP = os.environ.get("ACCOUNTING_IP")
ACCOUNTING_PORT = os.environ.get("ACCOUNTING_PORT")
ACCOUNTING_PROTOCOL = os.environ.get("ACCOUNTING_PROTOCOL")


# Address Node (ex: "http://127.0.0.1:9053/")
NODE_ADDRESS = "http://%s:%s/" % (os.environ.get("NODE_HOST"), os.environ.get("NODE_PORT", "9052"))

# Custom verifier address
VERIFIER_ADDRESS = "http://%s:%s/" % (os.environ.get("VERIFIER_HOST"), os.environ.get("VERIFIER_PORT", "9001"))

# Secret Key of Node(apiKey) (ex: "623f4e8e440007f45020afabbf56d8ba43144778757ea88497c794ad529a0433")
API_KEY = os.environ.get("SECRET")

# Explorer ergo (ex: https://api.ergoplatform.com/)
ERGO_EXPLORER_ADDRESS = "https://%s/" % (os.environ.get("ERGO_EXPLORER_ADDRESS"))

# Number of call logger in level critical
NUMBER_OF_LOG = os.environ.get("NUMBER_OF_LOG")

import os

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get("DEBUGGING") == "DEBUG"

# # Database
# # https://docs.djangoproject.com/en/2.2/ref/settings/#databases
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

# Address Node (ex: "http://127.0.0.1:9053/")
NODE_ADDRESS = "http://%s:%s/" % (os.environ.get("NODE_HOST"), os.environ.get("NODE_PORT", "9052"))

# Explorer ergo (ex: https://api.ergoplatform.com/)
ERGO_EXPLORER_ADDRESS = "https://%s/" % (os.environ.get("ERGO_EXPLORER_ADDRESS",
                                                        'api-testnet.ergoplatform.com'))

# Custom verifier address
VERIFIER_ADDRESS = "http://%s:%s/" % (os.environ.get("VERIFIER_HOST"), os.environ.get("VERIFIER_PORT", "9001"))

# Secret Key of Node(apiKey) (ex: "623f4e8e440007f45020afabbf56d8ba43144778757ea88497c794ad529a0433")
API_KEY = os.environ.get("SECRET")

# Access url for accounting system
ACCOUNTING_IP = os.environ.get("ACCOUNTING_IP")
ACCOUNTING_PORT = int(os.environ.get("ACCOUNTING_PORT"))
ACCOUNTING_PROTOCOL = os.environ.get("ACCOUNTING_PROTOCOL")

# Allowed Hosts
ALLOWED_HOSTS = os.environ.get('HOST', "").split(",")

# Logging config
# You may want to uncomment mail handler in production!
# you should get the logger like this whenever you need it: logging.getLogger(__name__)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'DEBUG')
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(asctime)s %(levelname)-8s [%(module)s:%(funcName)s:%(lineno)d] %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },
    'handlers': {
        'console': {
            'level': LOG_LEVEL,
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'formatter': 'verbose',
            'filename': os.path.join(BASE_DIR, '.important.log')
        },
        # 'mail': {
        #     'level': 'CRITICAL',
        #     'class': 'django.utils.log.AdminEmailHandler',
        #     'formatter': 'verbose',
        # },
    },
    'loggers': {
        'Api': {
            'handlers': ['console', 'file'],
            'propagate': True,
            'level': LOG_LEVEL,
        }
    }
}

# Number of call logger in level critical
NUMBER_OF_LOG = os.environ.get("NUMBER_OF_LOG")

# set your approprate broker url, e.g, rabbitmq or redis
CELERY_BROKER_URL = os.environ.get("BROKER_URL")

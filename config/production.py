# # Database
# # https://docs.djangoproject.com/en/2.2/ref/settings/#databases
import os

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'admin',
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

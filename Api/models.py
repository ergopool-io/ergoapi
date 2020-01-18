from pydoc import locate

from django.db import models
from frozendict import frozendict
import logging

logger = logging.getLogger(__name__)

CONFIGURATION_KEY_CHOICE = (
    ("POOL_BASE_FACTOR", "Pool base factor"),
    ("REWARD", "Reward"),
    ("REWARD_FACTOR", "Reward factor"),
    ("SHARE_CHUNK_SIZE", "Share chunk size")
)

CONFIGURATION_KEY_TO_TYPE = frozendict({
    'POOL_BASE_FACTOR': 'int',
    'REWARD': 'float',
    'REWARD_FACTOR': 'float',
    'SHARE_CHUNK_SIZE': 'int'
})

CONFIGURATION_DEFAULT_KEY_VALUE = frozendict({
    'POOL_BASE_FACTOR': 1000,
    'REWARD': 67.5,
    'REWARD_FACTOR': 1,
    'SHARE_CHUNK_SIZE': 10
})


class Block(models.Model):
    public_key = models.TextField(unique=True)
    msg = models.TextField(blank=True, null=True)
    tx_id = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return self.public_key


class ConfigurationManager(models.Manager):

    def __getattr__(self, attr):
        """
        overriding __gerattr__ to create new 2 attributes for Configuration.object based on KEY_CHOICES.
        :param attr:
        :return:
        """
        if attr in [key for (key, temp) in CONFIGURATION_KEY_CHOICE]:
            configurations = dict(self.all().values_list('key', 'value'))
            if attr in configurations:
                val = configurations[attr]
                val_type = CONFIGURATION_KEY_TO_TYPE[attr]

                # trying to convert value to value_type
                try:
                    val = locate(val_type)(val)
                    return val

                except:
                    # failed to convert, return default value
                    logger.error('Problem in configuration; {} with value {} is not compatible with type {}'
                                 .format(attr, val, val_type))
                    return CONFIGURATION_DEFAULT_KEY_VALUE[attr]

            return CONFIGURATION_DEFAULT_KEY_VALUE[attr]

        else:
            return super(ConfigurationManager, self).__getattribute__(attr)


class Configuration(models.Model):
    key = models.CharField(max_length=255, choices=CONFIGURATION_KEY_CHOICE, blank=False)
    value = models.CharField(max_length=255, blank=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = ConfigurationManager()

    def __str__(self):
        return self.key + ":" + str(self.value)


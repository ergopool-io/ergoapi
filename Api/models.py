from django.db import models

KEY_CHOICES = (
    ("POOL_DIFFICULTY_FACTOR", "POOL_DIFFICULTY_FACTOR"),
    ("REWARD", "REWARD"),
    ("REWARD_FACTOR", "REWARD_FACTOR"))

DEFAULT_KEY_VALUES = {
    'POOL_DIFFICULTY_FACTOR': 10,
    'REWARD_FACTOR': 1,
    'REWARD': 67.5
}


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
        if attr in [key for (key, temp) in KEY_CHOICES]:
            configurations = self.get_queryset().all()
            if attr not in configurations:
                return DEFAULT_KEY_VALUES[attr]
            else:
                return self.get_queryset().get(key=attr)
        else:
            return super(ConfigurationManager, self).__getattribute__(attr)


class Configuration(models.Model):
    key = models.CharField(max_length=255, choices=KEY_CHOICES, blank=False)
    value = models.FloatField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = ConfigurationManager()

    def __str__(self):
        return self.key + ":" + str(self.value)


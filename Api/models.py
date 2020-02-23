import logging

from django.db import models

logger = logging.getLogger(__name__)


class Block(models.Model):
    public_key = models.TextField(unique=True)
    msg = models.TextField(blank=True, null=True)
    tx_id = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return self.public_key


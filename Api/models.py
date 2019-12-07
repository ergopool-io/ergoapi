from django.db import models


class Block(models.Model):
    public_key = models.TextField(unique=True)
    msg = models.TextField(blank=True, null=True)
    tx_id = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return self.public_key

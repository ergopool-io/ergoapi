from django.db import models


class Block(models.Model):
    public_key = models.TextField(unique=True)
    msg = models.TextField()
    
    def __str__(self):
        return self.public_key


class NoModel(models.Model):
    pass


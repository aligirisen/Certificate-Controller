from django.db import models

class Username(models.Model):
    name = models.CharField(max_length=100)

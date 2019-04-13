from rest_framework import serializers
from . import models

class MobileUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.MobileUser
        fields = ('mobile', )
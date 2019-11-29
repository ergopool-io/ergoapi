from rest_framework import serializers
from rest_framework.exceptions import ValidationError


class ShareSerializer(serializers.Serializer):
    pk = serializers.CharField()
    nonce = serializers.CharField()
    d = serializers.CharField()
    w = serializers.CharField()

    def validate_d(self, value):
        try:
            return int(value)
        except:
            raise ValidationError(_("invalid number entered"))

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    class Meta:
        fields = ['pk', 'nonce', 'd', 'w']

from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from Api.models import Configuration


class ShareSerializer(serializers.Serializer):
    pk = serializers.CharField()
    nonce = serializers.CharField()
    d = serializers.CharField()
    w = serializers.CharField()

    def validate_d(self, value):
        try:
            return int(value)
        except:
            raise ValidationError("invalid number entered")

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    class Meta:
        fields = ['pk', 'nonce', 'd', 'w']


class ProofSerializer(serializers.Serializer):
    pk = serializers.CharField()
    msg_pre_image = serializers.CharField()
    leaf = serializers.CharField()
    levels = serializers.ListField(child=serializers.CharField())

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    class Meta:
        fields = ['pk', 'msg_pre_image', 'leaf', 'levels']


class TransactionSerializer(serializers.Serializer):
    pk = serializers.CharField()
    transaction = serializers.JSONField()

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    class Meta:
        fields = ['pk', 'transaction']


class ConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Configuration
        fields = ['key', 'value']

from rest_framework import serializers
from .models import Prediction, BlockedIP

class PredictionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Prediction
        fields = '__all__'

class BlockedIPSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockedIP
        fields = '__all__'

class TrafficDataSerializer(serializers.Serializer):
    """
    Serializer for incoming traffic data to be predicted.
    Accepts arbitrary JSON fields corresponding to model features.
    """
    # Using DictField to accept dynamic keys
    data = serializers.DictField()

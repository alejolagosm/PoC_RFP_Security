from rest_framework import serializers
from dojo.models import Alerts

class AlertsSerializers(serializers.ModelSerializer):
    user_id = serializers.PrimaryKeyRelatedField(
        queryset=__import__('dojo.models', fromlist=['Dojo_User']).Dojo_User.objects.all(),
        required=False,
        allow_null=True,
    )

    class Meta:
        model = Alerts
        fields = ['id', 'user_id', 'title', 'description', 'source', 'url', 'created']
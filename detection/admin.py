from django.contrib import admin
from .models import Prediction, BlockedIP

@admin.register(Prediction)
class PredictionAdmin(admin.ModelAdmin):
    list_display = ('id', 'timestamp', 'source_ip', 'attack_type', 'severity', 'confidence')
    list_filter = ('severity', 'attack_type')
    search_fields = ('source_ip',)

@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ('id', 'ip_address', 'blocked_at', 'reason')
    search_fields = ('ip_address', 'reason')

from django.contrib import admin
from .models import SystemSetting

@admin.register(SystemSetting)
class SystemSettingAdmin(admin.ModelAdmin):
    list_display = ('id', 'confidence_threshold', 'auto_block_severity', 'is_active')

from django.db import models

class SystemSetting(models.Model):
    confidence_threshold = models.IntegerField(default=80, help_text="Minimum confidence to trigger an alert.")
    auto_block_severity = models.CharField(max_length=20, choices=[('High', 'High Only'), ('Medium', 'Medium & High'), ('All', 'All Detected Attacks')], default='High')
    is_active = models.BooleanField(default=True, help_text="Global switch to activate or deactivate the detection system.")

    def save(self, *args, **kwargs):
        self.pk = 1
        super(SystemSetting, self).save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        pass # Prevent deletion

    @classmethod
    def load(cls):
        try:
            return cls.objects.get(pk=1)
        except cls.DoesNotExist:
            obj, created = cls.objects.get_or_create(pk=1)
            return obj

    def __str__(self):
        return "System Settings"

class GlobalStat(models.Model):
    total_processed = models.BigIntegerField(default=0)
    total_attacks = models.BigIntegerField(default=0)
    blocked_ips = models.BigIntegerField(default=0)

    def save(self, *args, **kwargs):
        self.pk = 1
        super(GlobalStat, self).save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        pass

    @classmethod
    def load(cls):
        try:
            return cls.objects.get(pk=1)
        except cls.DoesNotExist:
            obj, created = cls.objects.get_or_create(pk=1)
            if created:
                # Initialize with current counts on first load
                from detection.models import Prediction, BlockedIP
                obj.total_processed = Prediction.objects.count()
                obj.total_attacks = Prediction.objects.exclude(attack_type='Normal').count()
                obj.blocked_ips = BlockedIP.objects.count()
                obj.save()
            return obj

    def __str__(self):
        return "Global Statistics"

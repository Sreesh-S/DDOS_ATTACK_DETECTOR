from django.db import models

class Prediction(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    attack_type = models.CharField(max_length=100)
    confidence = models.FloatField()
    severity = models.CharField(max_length=20, choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')])
    raw_data = models.JSONField(help_text="Raw features used for prediction")

    def __str__(self):
        return f"{self.attack_type} detected at {self.timestamp}"

class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    blocked_at = models.DateTimeField(auto_now_add=True)
    reason = models.CharField(max_length=255)

    def __str__(self):
        return self.ip_address

class Report(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    total_processed = models.IntegerField()
    total_attacks = models.IntegerField()
    details = models.TextField()

    def __str__(self):
        return f"Report {self.created_at}"

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.db.models import F

@receiver(post_save, sender=Prediction)
def increment_prediction_stats(sender, instance, created, **kwargs):
    if created:
        from dashboard.models import GlobalStat
        stat = GlobalStat.load()
        stat.total_processed = F('total_processed') + 1
        if instance.attack_type != 'Normal':
            stat.total_attacks = F('total_attacks') + 1
            stat.save(update_fields=['total_processed', 'total_attacks'])
        else:
            stat.save(update_fields=['total_processed'])

@receiver(post_delete, sender=Prediction)
def decrement_prediction_stats(sender, instance, **kwargs):
    from dashboard.models import GlobalStat
    stat = GlobalStat.load()
    stat.total_processed = F('total_processed') - 1
    if instance.attack_type != 'Normal':
        stat.total_attacks = F('total_attacks') - 1
        stat.save(update_fields=['total_processed', 'total_attacks'])
    else:
        stat.save(update_fields=['total_processed'])

@receiver(post_save, sender=BlockedIP)
def increment_blocked_stats(sender, instance, created, **kwargs):
    if created:
        from dashboard.models import GlobalStat
        stat = GlobalStat.load()
        stat.blocked_ips = F('blocked_ips') + 1
        stat.save(update_fields=['blocked_ips'])

@receiver(post_delete, sender=BlockedIP)
def decrement_blocked_stats(sender, instance, **kwargs):
    from dashboard.models import GlobalStat
    stat = GlobalStat.load()
    stat.blocked_ips = F('blocked_ips') - 1
    stat.save(update_fields=['blocked_ips'])

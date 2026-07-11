from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
import joblib
import os
import pandas as pd
import numpy as np
from .serializers import PredictionSerializer, BlockedIPSerializer
from .models import Prediction, BlockedIP
from .ml.preprocess import Preprocessor

from django.apps import apps
from django.conf import settings
import threading

_predict_lock = threading.Lock()

# Load model and preprocessor at module level
BASE_DIR = settings.BASE_DIR
MODEL_PATH = os.path.join(BASE_DIR, 'detection', 'ml', 'model.pkl')
FEATURES_PATH = os.path.join(BASE_DIR, 'detection', 'ml', 'features.json')

def get_model():
    return apps.get_app_config('detection').ml_model

def get_preprocessor():
    return apps.get_app_config('detection').ml_preprocessor

class PredictAPIView(APIView):
    def get(self, request):
        """
        Provides information on how to use the API.
        """
        return Response({
            "message": "Use POST request to get predictions.",
            "usage": {
                "method": "POST",
                "url": "/api/predict/",
                "headers": {"Content-Type": "application/json"},
                "body": {
                    "feature_name_1": "value",
                    "feature_name_2": "value"
                }
            }
        }, status=status.HTTP_200_OK)

    def post(self, request):
        from dashboard.models import SystemSetting
        setting = SystemSetting.load()
        # Ensure we still process and log traffic, just skip blocking if deactivated
            
        input_data = request.data
        is_batch = isinstance(input_data, list)
        items = input_data if is_batch else [input_data]
        
        # We will collect IPs to check for blocking later
        source_ips = [item.get('Source IP', request.META.get('REMOTE_ADDR')) for item in items]
        destination_ips = [item.get('Destination IP', '0.0.0.0') for item in items]
        
        # Check if IPs are already blocked
        blocked_ips_in_db = set(BlockedIP.objects.filter(ip_address__in=source_ips).values_list('ip_address', flat=True))

        model = get_model()
        if not model:
            return Response({"error": "Model not available"}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        
        preprocessor = get_preprocessor()
        
        # Preprocess features
        try:
            features_df = preprocessor.preprocess(items)
        except Exception as e:
            return Response({"error": f"Preprocessing failed: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
            
    # Predict
        try:
            with _predict_lock:
                with joblib.parallel_backend("threading", n_jobs=1):
                    predictions = model.predict(features_df)
                    # Probabilities if supported
                    try:
                        probs = model.predict_proba(features_df)
                        confidences = np.max(probs, axis=1) * 100
                    except:
                        confidences = [100.0 if p != 'Normal' else 0.0 for p in predictions]

        except Exception as e:
            return Response({"error": f"Prediction failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        predictions_to_create = []
        new_blocks = []
        response_data_list = []

        for i in range(len(items)):
            source_ip = source_ips[i]
            destination_ip = destination_ips[i]
            prediction = predictions[i]
            confidence = float(confidences[i])
            item_raw_data = items[i]
            
            if source_ip in blocked_ips_in_db:
                # Flow blocked, don't record prediction or just record as blocked? Keep API backwards compatible
                response_data_list.append({
                    "error": "IP is blocked",
                    "ip": source_ip,
                    "status": "blocked"
                })
                continue
                
            # Determine Severity
            if prediction != "Normal":
                if confidence >= setting.confidence_threshold:
                    if "DDoS" in prediction or "Hulk" in prediction:
                        severity = "High"
                    else:
                        severity = "Medium"
                else:
                    severity = "Low"
            else:
                severity = "Low"

            # Prepare DB object
            predictions_to_create.append(Prediction(
                source_ip=source_ip,
                destination_ip=destination_ip,
                attack_type=prediction,
                confidence=confidence,
                severity=severity,
                raw_data=item_raw_data
            ))

            # Mitigation: Check auto_block_severity setting
            is_blocked = False
            if setting.is_active and prediction != "Normal" and severity != "Low":
                should_block = False
                if setting.auto_block_severity == 'All':
                    should_block = True
                elif setting.auto_block_severity == 'Medium' and severity in ['Medium', 'High']:
                    should_block = True
                elif setting.auto_block_severity == 'High' and severity == 'High':
                    should_block = True
                    
                if should_block:
                    if source_ip not in blocked_ips_in_db:
                        new_blocks.append(BlockedIP(
                            ip_address=source_ip,
                            reason=f"Detected {prediction} with {confidence:.2f}% confidence"
                        ))
                        blocked_ips_in_db.add(source_ip) # Prevent duplicate creations in this batch
                    is_blocked = True

            response_data_list.append({
                "prediction": prediction,
                "confidence": confidence,
                "severity": severity,
                "blocked": is_blocked
            })

        # Bulk save to DB
        try:
            if predictions_to_create:
                Prediction.objects.bulk_create(predictions_to_create)
                
                # Manually update GlobalStat since bulk_create doesn't trigger signals
                from dashboard.models import GlobalStat
                from django.db.models import F
                
                num_predictions = len(predictions_to_create)
                num_attacks = sum(1 for p in predictions_to_create if p.attack_type != 'Normal')
                
                GlobalStat.objects.filter(pk=1).update(
                    total_processed=F('total_processed') + num_predictions,
                    total_attacks=F('total_attacks') + num_attacks
                )
                
            if new_blocks:
                BlockedIP.objects.bulk_create(new_blocks, ignore_conflicts=True)
                
                # Update blocked_ips count
                from dashboard.models import GlobalStat
                blocked_count = BlockedIP.objects.count()
                GlobalStat.objects.filter(pk=1).update(blocked_ips=blocked_count)
        except Exception as db_err:
            import logging
            logging.warning(f"Database write failed (likely read-only serverless environment): {db_err}")

        # Return list if input was list, else single object
        if is_batch:
            return Response(response_data_list, status=status.HTTP_200_OK)
        else:
            # If the only item was already blocked, it returned an error dict.
            if len(response_data_list) > 0 and "error" in response_data_list[0]:
                return Response(response_data_list[0], status=status.HTTP_403_FORBIDDEN)
            return Response(response_data_list[0] if response_data_list else {}, status=status.HTTP_200_OK)

class StatsView(APIView):
    def get(self, request):
        from dashboard.models import GlobalStat
        stat = GlobalStat.load()
        total_requests = stat.total_processed
        total_attacks = stat.total_attacks
        blocked_ips = stat.blocked_ips
        
        # Recent logs
        recent_logs = Prediction.objects.order_by('-timestamp')[:10]
        recent_serializer = PredictionSerializer(recent_logs, many=True)
        
        # Blocked IPs
        recent_blocks = BlockedIP.objects.order_by('-blocked_at')[:5]
        blocked_serializer = BlockedIPSerializer(recent_blocks, many=True)

        # Attack distribution
        from django.db.models import Count
        distribution = Prediction.objects.exclude(attack_type='Normal').values('attack_type').annotate(count=Count('attack_type'))
        
        # Traffic Time Series (Last 10 minutes)
        from django.utils import timezone
        import datetime
        from django.db.models.functions import TruncMinute
        
        now = timezone.now().replace(second=0, microsecond=0)
        ten_mins_ago = now - datetime.timedelta(minutes=10)
        
        traffic_data = Prediction.objects.filter(timestamp__gte=ten_mins_ago)\
            .annotate(minute=TruncMinute('timestamp'))\
            .values('minute', 'severity')\
            .annotate(count=Count('id'))\
            .order_by('minute')
            
        traffic_dict = {}
        for entry in traffic_data:
            local_entry_dt = timezone.localtime(entry['minute'])
            minute_str = local_entry_dt.strftime('%I:%M %p').lstrip('0')
            if minute_str not in traffic_dict:
                traffic_dict[minute_str] = {'Low': 0, 'Medium': 0, 'High': 0}
            traffic_dict[minute_str][entry['severity']] = entry['count']
            
        traffic_labels = []
        traffic_low = []
        traffic_medium = []
        traffic_high = []
        
        for i in range(10, -1, -1):
            minute_dt = now - datetime.timedelta(minutes=i)
            local_minute_dt = timezone.localtime(minute_dt)
            minute_str = local_minute_dt.strftime('%I:%M %p').lstrip('0')
            traffic_labels.append(minute_str)
            
            # Determine divisor for rate per second
            if i == 0:
                current_second = float(timezone.now().second)
                divisor = current_second if current_second > 0 else 1.0
            else:
                divisor = 60.0
                
            if minute_str in traffic_dict:
                low_val = traffic_dict[minute_str].get('Low', 0)
                traffic_low.append(round(low_val / divisor, 2))
                med_val = traffic_dict[minute_str].get('Medium', 0)
                traffic_medium.append(round(med_val / divisor, 2))
                high_val = traffic_dict[minute_str].get('High', 0)
                traffic_high.append(round(high_val / divisor, 2))
            else:
                traffic_low.append(0.0)
                traffic_medium.append(0.0)
                traffic_high.append(0.0)

        from dashboard.models import SystemSetting
        setting = SystemSetting.load()
        
        return Response({
            "is_active": setting.is_active,
            "total_requests": total_requests,
            "total_attacks": total_attacks,
            "blocked_ips": blocked_ips,
            "recent_logs": recent_serializer.data,
            "blocked_table": blocked_serializer.data,
            "distribution": distribution,
            "traffic_labels": traffic_labels,
            "traffic_low": traffic_low,
            "traffic_medium": traffic_medium,
            "traffic_high": traffic_high
        })

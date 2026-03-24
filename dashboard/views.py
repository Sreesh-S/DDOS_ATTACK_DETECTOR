from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
import os
from datetime import datetime
from django.conf import settings as django_settings
from detection.models import Prediction, BlockedIP, Report
from .models import SystemSetting
from django.db.models import Count
def index(request):
    # Overall Stats
    from .models import GlobalStat
    stat = GlobalStat.load()
    total_processed = stat.total_processed
    total_attacks = stat.total_attacks
    blocked_count = stat.blocked_ips
    
    # Recent Attacks
    recent_attacks = Prediction.objects.exclude(attack_type='Normal').order_by('-timestamp')[:5]
    
    # Blocked IPs
    blocked_ips = BlockedIP.objects.order_by('-blocked_at')[:5]
    
    context = {
        'total_processed': total_processed,
        'total_attacks': total_attacks,
        'blocked_count': blocked_count,
        'recent_attacks': recent_attacks,
        'blocked_ips': blocked_ips,
    }
    return render(request, 'dashboard/index.html', context)

import geoip2.database

def get_geo_location(ip, reader):
    """Helper function to get geo location from IP. Returns dict with country, city, lat, lon."""
    if not ip or not isinstance(ip, str):
        return {'country': 'Unknown', 'city': 'Unknown', 'lat': 0, 'lon': 0}

    if ip.startswith('192.168.') or ip.startswith('10.') or ip == '127.0.0.1':
        # Use location around Mangalam College, Ettumanoor, Kerala for local Wi-Fi testing
        import random
        # Seed random to make mock locations consistent per IP
        random.seed(ip)
        
        # Base coordinates for Ettumanoor/Mangalam College area (approx)
        base_lat = 9.6630
        base_lon = 76.5600
        
        # Add tiny random jitter so different local IPs show up distinctly around the campus map
        lat_jitter = random.uniform(-0.005, 0.005)
        lon_jitter = random.uniform(-0.005, 0.005)
        
        return {
            'country': 'India', 
            'city': 'Ettumanoor, Kerala (Local Network)', 
            'lat': base_lat + lat_jitter, 
            'lon': base_lon + lon_jitter
        }

    try:
        response = reader.city(ip)
        return {
            'country': response.country.name or 'Unknown',
            'city': response.city.name or 'Unknown',
            'lat': response.location.latitude or 0,
            'lon': response.location.longitude or 0
        }
    except Exception:
        return {'country': 'Unknown', 'city': 'Unknown', 'lat': 0, 'lon': 0}

def logs(request):
    # Fetch all attacks (excluding Normal) ordered by time
    logs_qs = Prediction.objects.exclude(attack_type='Normal').order_by('-timestamp')[:100] # Limit to last 100 for now
    
    # Enrich logs with Geo-IP data
    db_path = os.path.join(django_settings.BASE_DIR, 'GeoLite2-City.mmdb')
    enriched_logs = []
    
    try:
        reader = geoip2.database.Reader(db_path)
        for log in logs_qs:
            geo_info = get_geo_location(log.source_ip, reader)
            # Create a dict wrapper so we can add arbitrary attributes easily in template
            log_data = {
                'id': log.id,
                'timestamp': log.timestamp,
                'source_ip': log.source_ip,
                'attack_type': log.attack_type,
                'confidence': log.confidence,
                'severity': log.severity,
                'country': geo_info['country'],
                'city': geo_info['city'],
                'lat': geo_info['lat'],
                'lon': geo_info['lon']
            }
            enriched_logs.append(log_data)
        reader.close()
    except Exception as e:
        print(f"GeoIP Error: {e}")
        # Fallback if DB is missing or error occurs
        enriched_logs = []
        for log in logs_qs:
            enriched_logs.append({
                'id': log.id,
                'timestamp': log.timestamp,
                'source_ip': log.source_ip,
                'attack_type': log.attack_type,
                'confidence': log.confidence,
                'severity': log.severity,
                'country': 'Unknown',
                'city': 'Unknown',
                'lat': 0,
                'lon': 0
            })
            
    return render(request, 'dashboard/logs.html', {'logs': enriched_logs})

def blocked_ips(request):
    blocked_list = BlockedIP.objects.all().order_by('-blocked_at')
    return render(request, 'dashboard/blocked_ips.html', {'blocked_list': blocked_list})

def settings(request):
    setting = SystemSetting.load()
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'save_settings':
            confidence = request.POST.get('confidence_threshold')
            if confidence:
                setting.confidence_threshold = int(confidence)
                
            auto_block = request.POST.get('auto_block_severity')
            if auto_block in dict(SystemSetting._meta.get_field('auto_block_severity').choices):
                setting.auto_block_severity = auto_block
                
            setting.save()
            messages.success(request, 'Settings saved successfully.')
            
        elif action == 'reset_settings':
            setting.confidence_threshold = 80
            setting.auto_block_severity = 'High'
            setting.save()
            messages.success(request, 'Settings reset to defaults.')
            
        elif action == 'clear_logs':
            Prediction.objects.all().delete()
            Report.objects.all().delete()
            BlockedIP.objects.all().delete()
            
            # Reset Global Stats
            from .models import GlobalStat
            stat = GlobalStat.load()
            stat.total_processed = 0
            stat.total_attacks = 0
            stat.blocked_ips = 0
            stat.save()
            
            messages.success(request, 'All logs, reports, and blocked IPs have been cleared.')
            
        return redirect('settings')

    db_path = django_settings.DATABASES['default']['NAME']
    try:
        db_size_mb = os.path.getsize(db_path) / (1024 * 1024)
        db_size_str = f"{db_size_mb:.2f} MB"
    except Exception:
        db_size_str = "Unknown"

    model_path = os.path.join(django_settings.BASE_DIR, 'detection', 'ml', 'model.pkl')
    try:
        mtime = os.path.getmtime(model_path)
        last_retrained = datetime.fromtimestamp(mtime).strftime('%b %d, %Y %I:%M %p')
    except Exception:
        last_retrained = "Unknown"

    return render(request, 'dashboard/settings.html', {
        'setting': setting,
        'db_size': db_size_str,
        'last_retrained': last_retrained
    })

def unblock_ip(request, id):
    ip_obj = get_object_or_404(BlockedIP, id=id)
    ip_obj.delete()
    return redirect('blocked_ips')

def toggle_system_status(request):
    if request.method == 'POST':
        setting = SystemSetting.load()
        setting.is_active = not setting.is_active
        setting.save()
        status_text = "activated" if setting.is_active else "deactivated"
        messages.success(request, f'System has been {status_text}.')
    return redirect('home')

import csv
from django.http import HttpResponse

def export_report(request):
    # Fetch recent logs
    logs = Prediction.objects.order_by('-timestamp')[:1000]
    
    # Create the HttpResponse object with the appropriate CSV header.
    response = HttpResponse(
        content_type='text/csv',
        headers={'Content-Disposition': 'attachment; filename="ddos_report.csv"'},
    )

    writer = csv.writer(response)
    # Write the header row
    writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Attack Type', 'Severity', 'Confidence'])

    # Write data rows
    for log in logs:
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.source_ip,
            log.destination_ip,
            log.attack_type,
            log.severity,
            f"{log.confidence:.2f}%"
        ])

    return response

import psutil
from django.http import JsonResponse

def network_flow(request):
    """Renders the Network Flow dashboard page."""
    return render(request, 'dashboard/network_flow.html')

import time
import subprocess
import re
import platform

# Cache to store previous stats for rate calculation
last_network_stats = {}

def get_wifi_info():
    """Extracts Wi-Fi details on Windows using netsh."""
    wifi_data = {}
    if platform.system() != 'Windows':
        return wifi_data
        
    try:
        # Run netsh command, decode ignoring errors
        output = subprocess.check_output(
            'netsh wlan show interfaces', 
            shell=True, 
            stderr=subprocess.STDOUT
        ).decode('utf-8', errors='ignore')
        
        # Simple regex parsing
        m_ssid = re.search(r'SSID\s*:\s*(.*)', output)
        m_radio = re.search(r'Radio type\s*:\s*(.*)', output)
        m_rx = re.search(r'Receive rate \(Mbps\)\s*:\s*(.*)', output)
        m_tx = re.search(r'Transmit rate \(Mbps\)\s*:\s*(.*)', output)
        m_sig = re.search(r'Signal\s*:\s*(.*)', output)
        m_band = re.search(r'Band\s*:\s*(.*)', output)
        m_channel = re.search(r'Channel\s*:\s*(.*)', output)
        
        if m_ssid and m_ssid.group(1).strip() != '':
            wifi_data['ssid'] = m_ssid.group(1).strip()
            wifi_data['radio'] = m_radio.group(1).strip() if m_radio else 'Unknown'
            wifi_data['rx_rate'] = m_rx.group(1).strip() if m_rx else 'Unknown'
            wifi_data['tx_rate'] = m_tx.group(1).strip() if m_tx else 'Unknown'
            wifi_data['signal'] = m_sig.group(1).strip() if m_sig else 'Unknown'
            wifi_data['band'] = m_band.group(1).strip() if m_band else 'Unknown'
            wifi_data['channel'] = m_channel.group(1).strip() if m_channel else 'Unknown'
    except Exception as e:
        pass
        
    return wifi_data

def network_stats_api(request):
    """Returns live network interface statistics as JSON."""
    global last_network_stats
    stats = {}
    current_time = time.time()
    
    try:
        io_counters = psutil.net_io_counters(pernic=True)
        if_stats = psutil.net_if_stats()
        if_addrs = psutil.net_if_addrs()
        
        # Get wi-fi info once if on windows
        global_wifi_info = get_wifi_info()
        
        for iface, counters in io_counters.items():
            iface_info = if_stats.get(iface)
            is_up = iface_info.isup if iface_info else True
            
            if is_up and (counters.bytes_recv > 0 or counters.bytes_sent > 0):
                method = "Ethernet"
                if "wi-fi" in iface.lower() or "wireless" in iface.lower() or "wlan" in iface.lower():
                    method = "Wi-Fi"
                elif "loopback" in iface.lower() or iface == "lo":
                    method = "Loopback"
                
                # Fetch IP Addresses (IPv4 usually family=2)
                ipv4 = "Unknown"
                mac = "Unknown"
                if iface in if_addrs:
                    for addr in if_addrs[iface]:
                        if hasattr(psutil, 'AF_LINK') and addr.family == psutil.AF_LINK: # MAC Address
                            mac = addr.address
                        elif addr.family == 2: # AF_INET (IPv4)
                            ipv4 = addr.address
                            
                # Attach Wi-Fi details if this is the Wi-Fi interface and we found SSID
                wifi_info = None
                if method == "Wi-Fi" and global_wifi_info.get('ssid'):
                    wifi_info = global_wifi_info
                
                # Calculate differentials
                pkts_sent_sec = 0
                pkts_recv_sec = 0
                bytes_sent_sec = 0
                bytes_recv_sec = 0
                
                if iface in last_network_stats:
                    prev_stats = last_network_stats[iface]
                    time_diff = current_time - prev_stats['timestamp']
                    if time_diff > 0:
                        pkts_sent_sec = max(0, (counters.packets_sent - prev_stats['packets_sent']) / time_diff)
                        pkts_recv_sec = max(0, (counters.packets_recv - prev_stats['packets_recv']) / time_diff)
                        bytes_sent_sec = max(0, (counters.bytes_sent - prev_stats['bytes_sent']) / time_diff)
                        bytes_recv_sec = max(0, (counters.bytes_recv - prev_stats['bytes_recv']) / time_diff)
                        
                # Update Cache
                last_network_stats[iface] = {
                    'timestamp': current_time,
                    'packets_sent': counters.packets_sent,
                    'packets_recv': counters.packets_recv,
                    'bytes_sent': counters.bytes_sent,
                    'bytes_recv': counters.bytes_recv
                }
                
                stats[iface] = {
                    "method": method,
                    "ipv4": ipv4,
                    "mac": mac,
                    "wifi_info": wifi_info,
                    "packets_sent_total": counters.packets_sent,
                    "packets_recv_total": counters.packets_recv,
                    "packets_sent_sec": round(pkts_sent_sec, 1),
                    "packets_recv_sec": round(pkts_recv_sec, 1),
                    "bytes_sent_sec": round(bytes_sent_sec, 1),
                    "bytes_recv_sec": round(bytes_recv_sec, 1),
                    "bytes_sent": counters.bytes_sent,
                    "bytes_recv": counters.bytes_recv,
                    "errin": counters.errin,
                    "errout": counters.errout,
                    "dropin": counters.dropin,
                    "dropout": counters.dropout
                }
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
        
    # Get global network flows/attacks for the UI
    try:
        from detection.models import Prediction
        from django.utils import timezone
        from datetime import timedelta
        
        # Consider recent traffic (last 1 minute)
        time_threshold = timezone.now() - timedelta(minutes=1)
        recent_preds = Prediction.objects.filter(timestamp__gte=time_threshold)
        
        normal_count = recent_preds.filter(attack_type='Normal').count()
        attack_count = recent_preds.exclude(attack_type='Normal').count()
    except Exception:
        normal_count = 0
        attack_count = 0
        
    return JsonResponse({
        "interfaces": stats,
        "global_normal": normal_count,
        "global_attack": attack_count
    })

def latest_alerts(request):
    """API endpoint to poll for recent attacks to trigger desktop alerts."""
    try:
        from detection.models import Prediction
        from django.utils import timezone
        from datetime import timedelta
        
        # Look for attacks in the last 15 seconds
        time_threshold = timezone.now() - timedelta(seconds=15)
        recent_attacks = Prediction.objects.exclude(attack_type='Normal').filter(timestamp__gte=time_threshold).order_by('-timestamp')
        
        alerts = []
        for attack in recent_attacks:
            alerts.append({
                'id': attack.id,
                'timestamp': attack.timestamp.isoformat(),
                'source_ip': attack.source_ip,
                'attack_type': attack.attack_type,
                'confidence': attack.confidence,
                'severity': attack.severity,
                'status': 'Blocked' if attack.severity == 'High' else 'Detected'
            })
            
        return JsonResponse({'alerts': alerts})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def attack_details(request, log_id):
    """View to show details of a specific attack, including AI Explanation."""
    from detection.models import Prediction
    log = get_object_or_404(Prediction, id=log_id)
    return render(request, 'dashboard/attack_details.html', {'log': log})

def api_shap_values(request, log_id):
    """API endpoint to generate SHAP values for a specific prediction."""
    try:
        from detection.models import Prediction
        import joblib
        import shap
        import pandas as pd
        import numpy as np
        
        log = get_object_or_404(Prediction, id=log_id)
        
        if log.attack_type == 'Normal':
            return JsonResponse({'error': 'Normal traffic doesn\'t have attack explanations.'}, status=400)
            
        if not log.raw_data:
            return JsonResponse({'error': 'No raw feature data available for this attack log.'}, status=404)
            
        model_path = os.path.join(django_settings.BASE_DIR, 'detection', 'ml', 'model.pkl')
        if not os.path.exists(model_path):
            return JsonResponse({'error': 'ML model file not found.'}, status=404)
            
        model = joblib.load(model_path)
        
        # In this project, raw_data is stored as a JSON dict from feature_extractor
        if isinstance(log.raw_data, str):
            import json
            raw_features = json.loads(log.raw_data)
        else:
            raw_features = log.raw_data
            
        # Ensure correct feature order
        from feature_extractor import FEATURES_ORDER
        # Build 1D numpy array
        feature_vector = [float(raw_features.get(f, 0.0)) for f in FEATURES_ORDER]
        X = np.array([feature_vector])
        
        explainer = shap.TreeExplainer(model)
        # SHAP returns an explainer object. For TreeExplainer, shap_values might be a list (multiclass) or array
        shap_values = explainer.shap_values(X)
        
        # For RandomForest, shap_values typically returns a list of arrays (one for each class)
        # Or a single array for binary.
        # We want the explanation for the predicted class.
        if isinstance(shap_values, list):
            # Try to get the index of the predicted class, or just max sum class
            # Since we don't have the original class label encoder, we'll just take the absolute mean impact across all classes or the largest magnitude
            # Let's take the impact on the class that caused the attack.
            # Simplified: just look at magnitude of feature impact overall
            abs_shap = np.abs(np.array(shap_values)).mean(axis=0)[0] 
        else:
            if len(shap_values.shape) == 3: # Multiclass (n_samples, n_features, n_classes) in newer shap versions
                abs_shap = np.abs(shap_values[0]).mean(axis=1) # Average influence across classes
            else:
                abs_shap = np.abs(shap_values[0])
                
        # Get top features
        top_indices = np.argsort(-abs_shap)[:10] # Top 10
        
        explanations = []
        for idx in top_indices:
            feat_name = FEATURES_ORDER[idx]
            feat_val = feature_vector[idx]
            impact = float(abs_shap[idx])
            
            # Format output nicely
            val_str = f"{feat_val:.2f}" if feat_val > 0.01 else f"{feat_val:.4f}"
            
            if impact > 0: # Only include features that had an impact
                explanations.append({
                    'feature': feat_name,
                    'value': val_str,
                    'impact': impact
                })
                
        return JsonResponse({'features': explanations})
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({'error': str(e)}, status=500)

def test_system(request):
    """View to render the attack simulation panel."""
    return render(request, 'dashboard/test_system.html')

active_simulation_process = None

def api_run_simulation(request):
    """API endpoint to trigger the background attack simulation continuously."""
    global active_simulation_process
    if request.method == 'POST':
        try:
            import subprocess
            import sys
            
            # Stop any existing simulation if it's already running
            if active_simulation_process and active_simulation_process.poll() is None:
                active_simulation_process.terminate()
            
            script_path = os.path.join(django_settings.BASE_DIR, 'attack_simulator.py')
            if not os.path.exists(script_path):
                return JsonResponse({'error': 'Simulation script not found.'}, status=404)
                
            # Run the simulation script asynchronously for 24 hours (continuous until stopped)
            active_simulation_process = subprocess.Popen([sys.executable, script_path, '86400'])
            
            return JsonResponse({'status': 'Simulation started continuously. Traffic will spike until stopped.'})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Invalid request method.'}, status=400)

def api_stop_simulation(request):
    """API endpoint to stop the background attack simulation."""
    global active_simulation_process
    if request.method == 'POST':
        try:
            if active_simulation_process and active_simulation_process.poll() is None:
                active_simulation_process.terminate()
                active_simulation_process = None
                return JsonResponse({'status': 'Simulation stopped successfully.'})
            else:
                return JsonResponse({'status': 'No simulation was currently running.'})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Invalid request method.'}, status=400)


from django.urls import path
from . import views

urlpatterns = [
    path('dashboard/', views.index, name='dashboard'),
    path('logs/', views.logs, name='logs'),
    path('blocked-ips/', views.blocked_ips, name='blocked_ips'),
    path('unblock/<int:id>/', views.unblock_ip, name='unblock_ip'),
    path('settings/', views.settings, name='settings'),
    path('toggle-status/', views.toggle_system_status, name='toggle_status'),
    path('export/', views.export_report, name='export_report'),
    path('network-flow/', views.network_flow, name='network_flow'),
    path('api/network-stats/', views.network_stats_api, name='network_stats_api'),
    path('api/network-stats/', views.network_stats_api, name='network_stats_api'),
    path('api/latest-alerts/', views.latest_alerts, name='latest_alerts'),
    path('attack-details/<int:log_id>/', views.attack_details, name='attack_details'),
    path('api/shap-values/<int:log_id>/', views.api_shap_values, name='api_shap_values'),
    path('test-system/', views.test_system, name='test_system'),
    path('api/run-simulation/', views.api_run_simulation, name='api_run_simulation'),
    path('api/stop-simulation/', views.api_stop_simulation, name='api_stop_simulation'),
    path('', views.index, name='home'), # Redirect root to dashboard
]

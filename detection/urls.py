from django.urls import path
from .views import PredictAPIView, StatsView

urlpatterns = [
    path('predict/', PredictAPIView.as_view(), name='predict'),
    path('stats/', StatsView.as_view(), name='stats'),
]

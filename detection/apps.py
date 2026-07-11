from django.apps import AppConfig
import os
import joblib
from django.conf import settings

class DetectionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'detection'
    
    ml_model = None
    ml_preprocessor = None

    def ready(self):
        # Prevent double-loading in runserver
        import sys
        if 'runserver' in sys.argv and os.environ.get('RUN_MAIN', None) != 'true':
            return
            
        print("Initializing ML Model for real-time detection...")
        base_dir = settings.BASE_DIR
        model_path = os.path.join(base_dir, 'detection', 'ml', 'model.pkl')
        features_path = os.path.join(base_dir, 'detection', 'ml', 'features.json')

        try:
            self.ml_model = joblib.load(model_path)
            if hasattr(self.ml_model, 'n_jobs'):
                self.ml_model.n_jobs = 1
            print(f"Model successfully loaded from {model_path}.")
        except Exception as e:
            print(f"Warning: Could not load the model. Real-time predictions will fail. Error: {e}")

        try:
            from .ml.preprocess import Preprocessor
            self.ml_preprocessor = Preprocessor(features_path)
        except Exception as e:
            print(f"Warning: Could not load the preprocessor. {e}")

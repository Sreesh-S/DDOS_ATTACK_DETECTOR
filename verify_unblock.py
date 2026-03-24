import os
import django
import urllib.request

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ddos_project.settings')
django.setup()

from detection.models import BlockedIP

def test_unblock():
    # 1. Create a dummy blocked IP
    ip = "1.2.3.4"
    obj, created = BlockedIP.objects.get_or_create(ip_address=ip, defaults={'reason': 'Test Block'})
    print(f"Created/Found Blocked IP: {obj.ip_address} (ID: {obj.id})")
    
    # 2. Trigger the unblock URL
    url = f"http://127.0.0.1:8000/unblock/{obj.id}/"
    print(f"Hitting URL: {url}")
    try:
        with urllib.request.urlopen(url) as response:
            print(f"Response Status: {response.status}")
    except Exception as e:
        print(f"Request failed: {e}")
        return

    # 3. Verify it's gone
    if not BlockedIP.objects.filter(id=obj.id).exists():
        print("SUCCESS: IP was unblocked and removed from DB.")
    else:
        print("FAILURE: IP still exists in DB.")

if __name__ == "__main__":
    test_unblock()

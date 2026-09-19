from app.db import SessionLocal
from app.models.db import Device, DeviceMetricSnapshot, Tenant
from app.routers.devices import delete_device
import uuid
from fastapi import Request

db = SessionLocal()

# Get first tenant
tenant = db.query(Tenant).first()
if not tenant:
    tenant = Tenant(id="tenant_test", name="test")
    db.add(tenant)
    db.commit()

tenant_id = tenant.id
device_id = str(uuid.uuid4())

# Create device
d = Device(id=device_id, tenant_id=tenant_id, hostname="api-test", management_address="1.1.1.1")
db.add(d)
db.commit()

# Create snapshot
s = DeviceMetricSnapshot(id=str(uuid.uuid4()), tenant_id=tenant_id, device_id=device_id)
db.add(s)
db.commit()

class DummyRequest:
    pass

class DummyUser:
    email = "test@example.com"
    username = "test"
    is_superuser = True
    tenants = [tenant_id]

# Call the function directly
try:
    delete_device(device_id=device_id, request=DummyRequest(), db=db, tenant_id=tenant_id, user=DummyUser())
    print("API ENDPOINT SUCCEEDED")
except Exception as e:
    print(f"API ENDPOINT FAILED: {e}")
    import traceback
    traceback.print_exc()

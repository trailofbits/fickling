"""
This is tutorial code for performing fault injections with PyTorchFi:
https://colab.research.google.com/drive/1BMB4LbsTU_K_YXUFzRyfIynpGu5Yhr1Y

Note you may need to run `pip install pytorchfi`
"""

import pickle

import torch
import torchvision.models as models
from pytorchfi.core import fault_injection

import fickling.analysis as analysis
from fickling.fickle import Pickled

# Load AlexNet

model = models.alexnet()
model.eval()

# Create a random image for testing

batch_size = 1
height = 224
width = 224
channels = 3

random_image = torch.rand((batch_size, channels, height, width))
output = model(random_image)
proper_label = list(torch.argmax(output, dim=1))[0].item()
print("Error-free label:", proper_label)

# Fickle the safe model

safe_model = Pickled.load(pickle.dumps(model))
safe_props = safe_model.properties

# Apply the fault injection

injected_model = fault_injection(
    model,
    batch_size,
    input_shape=[channels, height, width],
    layer_types=[torch.nn.Conv2d],
    use_cuda=False,
)

b, layer, C, H, W, err_val = [0], [2], [4], [2], [4], [10000]

injected_model = injected_model.declare_neuron_fi(
    batch=b, layer_num=layer, dim1=C, dim2=H, dim3=W, value=err_val
)

injected_output = injected_model(random_image)
injected_label = list(torch.argmax(injected_output, dim=1))[0].item()
print("Injected Label:", injected_label)

# Fickle the model with the fault injection

fickled_unsafe_model = Pickled.load(pickle.dumps(injected_model))
unsafe_props = fickled_unsafe_model.properties

# Try out Fickling's safety checks

print("\n\nIs this is_likely_safe?")

safety = analysis.check_safety(fickled_unsafe_model).to_dict()
print(safety["severity"])

# Test more safety checks

print("Do the AST properties match?")
if unsafe_props == safe_props:
    print("✅")
else:
    print("❌")

print("Do the ASTs match?")
if fickled_unsafe_model.ast == safe_model.ast:
    print("✅")
else:
    print("❌")

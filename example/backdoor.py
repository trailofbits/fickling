import torch
import torchvision.models as models
import pickle
from fickling.pickle import Pickled
import sys
import torchvision
import os
from pytorchfi.core import fault_injection

model = models.mobilenet_v2()

model.eval()

batch_size = 1
height = 224
width = 224
channels = 3

random_image = torch.rand((batch_size, channels, height, width))

output = model(random_image)


proper_label = list(torch.argmax(output, dim=1))[0].item()
print("Error-free label:", proper_label)

pfi_model = fault_injection(model, 
                     batch_size,
                     input_shape=[channels,height,width],
                     layer_types=[torch.nn.Conv2d],
                     use_cuda=False,
                     )

# print(pfi_model.print_pytorchfi_layer_summary())

b, layer, C, H, W, err_val = [0], [2], [4], [2], [4], [10000]

inj = pfi_model.declare_neuron_fi(batch=b, layer_num=layer, dim1=C, dim2=H, dim3=W, value=err_val)

inj_output = inj(random_image)

inj_label = list(torch.argmax(inj_output, dim=1))[0].item()
print("[Single Error] PytorchFI label:", inj_label)

fickled_model = Pickled.load(pickle.dumps(pfi_model))

print("\n\nIs this is_likely_safe?")

safety = fickled_model.is_likely_safe

if safety is False:
    print("❌")
else:
    print("✅")


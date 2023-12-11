import pickle
import os
import numpy as np
import torch
import builtins
import io
import types
import inspect
import ast 
import re
"""
This code adheres to the Pain Pickle implementation published here: https://ieeexplore.ieee.org/document/10062403.
Some changes have been made to their specified implementation for usability and integration.
"""
example_unsafe_modules = {"builtins",
                "os",
                "subprocess",
                "sys",
                "builtins",
                "socket",
}

example_safe_modules = {
    "numpy",
    "torch"
}

example_safe_functions = {"size", "arange"}

example_unsafe_functions = {"load", "loadtxt", "frombuffer"}

# Type A Restricted Unpicklers
# Paper: "The pairing of module and name must belong to a certain subset"
# For all types, class 1 refers to single-level acquisition and class 2 to recursive acquisition
class TypeA_ClassOne(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "numpy" and name in example_safe_functions:
            return getattr(np, name)
        else:
            raise pickle.UnpicklingError(f"global '{module}.{name}' is forbidden")

class TypeA_ClassTwo(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "numpy" and name in example_safe_functions:
            return super().find_class(module, name)
        else:
            raise pickle.UnpicklingError(f"global '{module}.{name}' is forbidden")


# Type B Restricted Unpicklers
# Paper: "The module parameter must belong to a certain subset and the name parameter must be restricted to 
# start with a certain string or adopt some loose rules, such as a blacklist mechanism"  
class TypeB_ClassOne(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "numpy" and name not in example_unsafe_functions:
            return getattr(np, name)
        else:
            raise pickle.UnpicklingError(f"global '{module}.{name}' is forbidden")

class TypeB_ClassTwo(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "numpy" and name not in example_unsafe_functions:
            return super().find_class(module, name)
        else:
            raise pickle.UnpicklingError(f"global '{module}.{name}' is forbidden")

# Type C Restricted Unpicklers
# Paper: "The module parameter must belong to a certain subset and the name parameter is not checked"
class TypeC_ClassOne(pickle.Unpickler):
    def find_class(self, module, name):
        # To use an allowlist mechanism, uncomment and use the following lines instead based on Listing 1
        #package_name = module.split(".")[0]
        #if package_name in example_safe_modules:
        if module == "numpy":
            #return super().find_class(module, name)
            return getattr(np, name)
        else:
            raise pickle.UnpicklingError(f"global '{module}.{name}' is forbidden")

class TypeC_ClassTwo(pickle.Unpickler):
    def find_class(self, module, name):
        #package_name = module.split(".")[0]
        #if package_name in example_safe_modules:
        if module == "numpy":
            return super().find_class(module, name)
        else:
            raise pickle.UnpicklingError(f"global '{module}.{name}' is forbidden")


# Type D Restricted Unpicklers
# Paper: "Only the module parameter is restricted to start with a specific string or use some loose rules, such as a blacklist mechanism"
# These examples use a blacklist mechanism
class TypeD_ClassOne(pickle.Unpickler):
    # Handled by Bypass Method 2
    def find_class(self, module, name):
        # For an alterate implementation, uncomment and use the following line 
        # if module.startswith("numpy"):
        if module not in example_unsafe_modules:
            return getattr(__import__(module, None, None, [name]), name)
        else:
            raise pickle.UnpicklingError(f"global '{module}.{name}' is forbidden")

class TypeD_ClassTwo(pickle.Unpickler):
    # Handled by Bypass Method 1
    def find_class(self, module, name):
        # For an alterate implementation, replace the following line with: "if module.startswith("numpy"):"
        if module not in example_unsafe_modules:
            return super().find_class(module, name)
        else:
            raise pickle.UnpicklingError(f"global '{module}.{name}' is forbidden")


class BenignNumpy(object):
    def __init__(self):
        self.a = 1

    def __reduce__(self):
        return (np.arange, (10,))

class MaliciousOs(object):
    def __init__(self):
        self.a = 1

    def __reduce__(self):
        return (os.system, ("echo 'hello world'",))

"""
#payload = BenignNumpy()
payload = MaliciousOs()

# Dump the input into a pickle file 
with open('tensor.pkl', 'wb') as f:
    pickle.dump(payload, f)

Unpickler = TypeA_ClassTwo

# Load input from the pickle file
with open('tensor.pkl', 'rb') as f:
    unpickler = Unpickler(f)
    loaded_data = unpickler.load()

print(loaded_data)
"""
def analyze_acquisition_method(method_source):
    # Idea: https://stackoverflow.com/questions/49713918/python-3-checking-if-a-function-was-called-on-by-another-function
    if 'getattr' in method_source: 
        return "Single-Level Acquisition"
    elif 'super().find_class' in method_source:
        return "Recursive Acquisition"
    else:
        return "Unknown Acquisition Method"

"""
def analyze_restriction_method(method_source):
    checks_module_and_name = re.search(r'\bmodule\b.*\bin\b.*\bname\b', method_source) or re.search(r'\bname\b.*\bin\b.*\bmodule\b', method_source)
    checks_module_only = re.search(r'\bmodule\b.*\bin\b', method_source) and not re.search(r'\bname\b.*\bin\b', method_source)
    loose_rules = re.search(r'\b(module|name)\b', method_source) and not checks_module_and_name

    if checks_module_and_name:
        return "Checks both module and name"
    elif checks_module_only:
        return "Checks only module"
    elif loose_rules:
        return "Loose rules applied"
    else:
        return "Unknown or no restrictions"
"""

def identify_unpickler_type(unpickler_class):
    if not issubclass(unpickler_class, pickle.Unpickler):
        return "Not a subclass of pickle.Unpickler"

    find_class_method = getattr(unpickler_class, "find_class", None)

    if find_class_method is None:
        return "No custom find_class method"

    source_code = inspect.getsource(find_class_method)
    acquisition_method = analyze_acquisition_method(source_code)
    #return acquisition_method
    arg_spec = inspect.getargspec(find_class_method)
    #print('NAMES   :', arg_spec[0])
    #print('*       :', arg_spec[1])
    #print('**      :', arg_spec[2])
    #print('defaults:', arg_spec[3])

    #args_with_defaults = arg_spec[0][-len(arg_spec[3]):]
    #print('args & defaults:', zip(args_with_defaults, arg_spec[3]))
    #restriction_method = analyze_restriction_method(source_code)
    #import pdb; pdb.set_trace()
    return acquisition_method#, restriction_method

"""
unpicklers = [TypeA_ClassOne, TypeA_ClassTwo, TypeB_ClassOne, TypeB_ClassTwo, TypeC_ClassOne, TypeC_ClassTwo, TypeD_ClassOne, TypeD_ClassTwo]

for x in unpicklers:
    result = identify_unpickler_type(x)
    print(result)
"""

unpickler_class = TypeA_ClassOne
find_class_method = getattr(unpickler_class, "find_class", None)
source_code = inspect.getsource(find_class_method)
acquisition_method = analyze_acquisition_method(source_code)
arg_spec = inspect.getargspec(find_class_method)
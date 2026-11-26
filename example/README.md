# Examples

* [hook_functions.py](hook_functions.py): Check the safety of all loaded pickle files using `fickling.always_check_safety()`
* [context_manager.py](context_manager.py): Halt the deserialization of a malicious pickle file with the fickling context manager
* [fault_injection.py](fault_injection.py): Perform a fault injection on a PyTorch model and then analyze the result with `check_safety`
* [inject_mobilenet.py](inject_mobilenet.py): Override the `eval` method of a ML model using fickling and apply `fickling.is_likely_safe` to the model file
* [inject_pytorch.py](inject_pytorch.py): Inject a model loaded from a PyTorch file with malicious code using the PyTorch module
* [numpy_poc.py](numpy_poc.py): Analyze a malicious payload passed to `numpy.load()`
* [trace_binary.py](trace_binary.py): Decompile a payload using the tracing module
* [identify_pytorch_file.py](identify_pytorch_file.py): Identify 2 PyTorch files that are different formats

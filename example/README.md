# Examples

* [hook_functions.py](https://github.com/trailofbits/fickling/blob/master/example/hook_functions.py): Check the safety of all loaded pickle files using `fickling.always_check_safety()`
* [context_manager.py](https://github.com/trailofbits/fickling/blob/master/example/context_manager.py): Halt the deserialization of a malicious pickle file with the fickling context manager 
* [fault_injection.py](https://github.com/trailofbits/fickling/blob/master/example/fault_injection.py): Perform a fault injection on a PyTorch model and then analyze the result with `check_safety`	 
* [inject_mobilenet.py](https://github.com/trailofbits/fickling/blob/master/example/inject_mobilenet.py): Override the `eval` method of a ML model using fickling and apply `fickling.is_likely_safe` to the model file 
* [inject_pytorch.py](https://github.com/trailofbits/fickling/blob/master/example/inject_pytorch.py): Inject a model loaded from a PyTorch file with malicious code using fickling’s PyTorch module 
* [numpy_poc.py](https://github.com/trailofbits/fickling/blob/master/example/numpy_poc.py): Analyze a malicious payload passed to `numpy.load()`
* [trace_binary.py](https://github.com/trailofbits/fickling/blob/master/example/trace_binary.py): Decompile a payload using the tracing module  
* [identify_pytorch_file.py](https://github.com/trailofbits/fickling/blob/master/example/identify_pytorch_file.py): Determine the file format type of 2 different PyTorch files
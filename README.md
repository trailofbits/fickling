# Fickling

Fickling is a decompiler, static analyzer, and bytecode rewriter for Python
[pickle](https://docs.python.org/3/library/pickle.html) object serializations.
You can use fickling to detect, analyze, reverse engineer, or even create 
malicious pickle or pickle-based files, including PyTorch files. 

## Key Features
- **Static Analysis**: Report detailed results of fickling’s `check_safety` in an easy-to-use JSON output 
- **Easy Integration**: Detect malicious files and halt processing using features like fickling.load(), a global function hook, and a context manager that streamlines integration into existing infrastructure 
- **Decompilation**: Decompiles pickled data streams into readable Python code, revealing the original serialized object 
- **Injection**: Rewrites bytecode to inject code into pickle and PyTorch files, aiding in exploit development and testing 
- **PyTorch Support**: Inspect and inject code into PyTorch files
- **Polyglot Support**: Identifies and creates polyglots for 7 PyTorch file formats

## Background 
Pickled Python objects are in fact bytecode that is interpreted by a stack-based
virtual machine built into Python called the "Pickle Machine". Fickling can take
pickled data streams and decompile them into human-readable Python code that,
when executed, will deserialize to the original serialized object. This is made 
possible by Fickling’s custom implementation of the PM. Fickling is safe to run 
on potentially malicious files because its PM symbolically executes code rather 
than overtly executing it.

The authors do not prescribe any meaning to the “F” in Fickling; it could stand
for “fickle,” … or something else. Divining its meaning is a personal journey
in discretion and is left as an exercise to the reader.

Learn more about fickling in our [blog post](https://blog.trailofbits.com/2021/03/15/never-a-dill-moment-exploiting-machine-learning-pickle-files/)
and [DEF CON AI Village 2021 talk](https://www.youtube.com/watch?v=bZ0m_H_dEJI).

## Installation

Fickling has been tested on Python 3.8 through Python 3.11 and has very few dependencies.
It can be installed through pip:

```bash
python -m pip install fickling
```

This installs both the library and the command line utility.

## Usage

Fickling is available as a CLI and a Python API. 

### CLI

```console
$ fickling pickled.data
result = [1, 2, 3, 4]
```

This is of course a simple example. However, Python pickle bytecode can run
arbitrary Python commands (such as `exec` or `os.system`) so it is a security
risk to unpickle untrusted data. You can test for common patterns of
malicious pickle files with the `--check-safety` option:

```console
$ fickling --check-safety pickled.data
Warning: Fickling failed to detect any overtly unsafe code, but the pickle file may still be unsafe.
Do not unpickle this file if it is from an untrusted source!
```

We do not recommend relying on the `--check-safety` option for critical use
cases at this point in time.

You can also safely trace the execution of the Pickle virtual machine without
exercising any malicious code with the `--trace` option.

Finally, you can inject arbitrary Python code that will be run on unpickling
into an existing pickle file with the `--inject` option.

### Python API 

```python
>>> import ast
>>> import pickle
>>> from fickling.pickle import Pickled
>>> fickled_object = Pickled.load(pickle.dumps([1, 2, 3, 4]))
>>> safety_results = fickled_object.check_safety().to_dict()
>>> print(safety_results['severity'])
LIKELY_SAFE
>>> print(ast.dump(fickled_object.ast, indent=4))
Module(
    body=[
        Assign(
            targets=[
                Name(id='result', ctx=Store())],
            value=List(
                elts=[
                    Constant(value=1),
                    Constant(value=2),
                    Constant(value=3),
                    Constant(value=4)],
                ctx=Load()))],
    type_ignores=[])
```

### Detection 

While we recommend relying on a safer file format such as safetensors, 
fickling can easily be integrated into existing infrastructure to halt 
pickling after detecting a malicious file. 

```python
>>> import pickle
>>> import fickling
>>> safe_list = [1, 2, 3]
>>> with open("safe.pkl", "wb") as file:
...     pickle.dump(safe_list, file)
>>> # Use fickling.load()
>>> with open("safe.pkl", "rb") as file:
...     print(fickling.load(file))
[1, 2, 3]
>>> # Use the context manager
>>> with fickling.check_safety():
...     with open("safe.pkl", "rb") as file:
...         print(pickle.load(file))
[1, 2, 3]
>>> # Use the global hook
>>> hook.run_hook()
>>> with open("safe.pkl", "rb") as file:
...         print(pickle.load(file))
[1, 2, 3]
```

### PyTorch Polyglots 
We currently support the following PyTorch file formats:
- PyTorch v0.1.1: Tar file with sys_info, pickle, storages, and tensors
- PyTorch v0.1.10: Stacked pickle files
- TorchScript v1.0: ZIP file with model.json and constants.pkl (a JSON file and a pickle file)
- TorchScript v1.1: ZIP file with model.json and attribute.pkl (a JSON file and a pickle file)
- TorchScript v1.3: ZIP file with data.pkl and constants.pkl (2 pickle files)
- TorchScript v1.4: ZIP file with data.pkl, constants.pkl, and version (2 pickle files and a folder)
- PyTorch v1.3: ZIP file containing data.pkl (1 pickle file)
- PyTorch model archive format: ZIP file that includes Python code files and pickle files
```python
>> import torch
>> import torchvision.models as models
>> from fickling.pytorch import PyTorchModelWrapper
>> model = models.mobilenet_v2()
>> torch.save(model, "mobilenet.pth")
>> fickled_model = PyTorchModelWrapper("mobilenet.pth")
>> print(fickled_model.formats)
Your file is most likely of this format:  PyTorch v1.3 
['PyTorch v1.3']
```

[Check out our examples to learn more about using fickling!](https://github.com/trailofbits/fickling/tree/master/example) 

## Contributing 
If you find a bug in fickling or want to implement new features, please 
raise an issue on our GitHub or contact us. 

## License

This utility was developed by [Trail of Bits](https://www.trailofbits.com/).
It is licensed under the [GNU Lesser General Public License v3.0](LICENSE).
[Contact us](mailto:opensource@trailofbits.com) if you're looking for an
exception to the terms.

© 2021, Trail of Bits.

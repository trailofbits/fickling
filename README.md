<p align="center">
<img src="https://github.com/trailofbits/fickling/blob/sh/readme/fickling_image.png" width="600" height="312">
</p>

# Fickling

Fickling is a decompiler, static analyzer, and bytecode rewriter for Python
[pickle](https://docs.python.org/3/library/pickle.html) object serializations.
You can use fickling to detect, analyze, reverse engineer, or even create
malicious pickle or pickle-based files, including PyTorch files.

[Key Features]() | [Background]() | [Installation]() | [Usage]() 
([CLI](), [Python API](), [Detection](), [PyTorch Polyglots]()) | [Getting Help]() | [License]()


## Key Features
* **Static Analysis**: Report detailed results from fickling’s `check_safety` in a usable JSON format
  * **Easy Integration**: Detect malicious files and halt deserialization using features like the context mananger, global hook,
and `fickling.load()` that streamline integration into existing infrastructure
* **Decompilation**: Decompiles pickled data streams into readable Python code, revealing the original serialized object
* **Injection**: Rewrite bytecode to inject code into pickle files and develop exploits in which anonymously shared pickle files can be an attack vector
* **PyTorch Support**: Inspect, analyze, and inject code into PyTorch files
  * **Polyglot-Aware Identification**: Identify what PyTorch file format type a file is without directly loading it
  * **Polyglot Creation**: Create polyglots between 7 different PyTorch file format types 


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
Both the library and command line utility can be installed through pip:

```bash
python -m pip install fickling
```

## Usage

Fickling is available as a CLI and Python API. 


### CLI

```console
$ fickling pickled.data
result = [1, 2, 3, 4]
```

While this is a simple example, Python pickle bytecode can run arbitrary
arbitrary Python commands (such as `exec` or `os.system`) so it is a security
risk to unpickle untrusted data. You can test for common patterns of
malicious pickle files with the `--check-safety` option:

```console
$ fickling --check-safety -p pickled.data
Warning: Fickling failed to detect any overtly unsafe code, but the pickle file may still be unsafe.
Do not unpickle this file if it is from an untrusted source!
```

The results of this analysis are saved in a JSON file by default.
Here's an an example of the JSON output from an analysis conducted on a malicious pickle file.

```
{
    "severity": "OVERTLY_MALICIOUS",
    "analysis": "Call to `eval(b'[5, 6, 7, 8]')` is almost certainly evidence of a malicious pickle file.
Variable `_var0` is assigned value `eval(b'[5, 6, 7, 8]')` but unused afterward; this is suspicious and indicative of a malicious pickle file",
    "detailed_results": {
        "AnalysisResult": {
            "OvertlyBadEval": "eval(b'[5, 6, 7, 8]')",
            "UnusedVariables": [
                "_var0",
                "eval(b'[5, 6, 7, 8]')"
            ]
        }
    }
}
```

You can also safely trace the execution of the Pickle virtual machine without
exercising any malicious code with the `--trace` option.

Finally, you can inject arbitrary Python code that will be run on unpickling
into an existing pickle file with the `--inject` option.


### Python API 

Similar to the CLI, you can use `check_safety` to analyze a pickle file
and even save the results as a JSON file. Ficking supports additional
analysis through its decompilation capabilities.

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

[While we recommend relying on a safer file format such as safetensors](https://huggingface.co/blog/safetensors-security-audit),
fickling can easily be integrated into existing infrastructure to halt
deserialization after detecting a malicious file.

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
We currently support inspecting, identifying, and creating polyglots between the following PyTorch file formats:
* **PyTorch v0.1.1**: Tar file with sys_info, pickle, storages, and tensors
* **PyTorch v0.1.10**: Stacked pickle files
* **TorchScript v1.0**: ZIP file with model.json and constants.pkl (a JSON file and a pickle file)
* **TorchScript v1.1**: ZIP file with model.json and attribute.pkl (a JSON file and a pickle file)
* **TorchScript v1.3**: ZIP file with data.pkl and constants.pkl (2 pickle files)
* **TorchScript v1.4**: ZIP file with data.pkl, constants.pkl, and version (2 pickle files and a folder)
* **PyTorch v1.3**: ZIP file containing data.pkl (1 pickle file)
* **PyTorch model archive format**: ZIP file that includes Python code files and pickle files
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

## Getting Help 
If you'd like to file a bug report or feature request, please use our [issues](https://github.com/trailofbits/fickling/issues) page.
Feel free to contact us or reach out in [Empire Hacking](https://slack.empirehacking.nyc/) for help using or extending fickling.

## License

This utility was developed by [Trail of Bits](https://www.trailofbits.com/).
It is licensed under the [GNU Lesser General Public License v3.0](LICENSE).
[Contact us](mailto:opensource@trailofbits.com) if you're looking for an
exception to the terms.

© 2021, Trail of Bits.

<p align="center">
<strong><i>We relish the thought of a day when pickling will no longer be used to deserialize untrusted files.</i></strong>
</p>

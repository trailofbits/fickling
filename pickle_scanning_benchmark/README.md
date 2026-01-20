# Malicious Pickle-files benchmark

A benchmark for malicious pickle file detection.

This repo allows to
- build a dataset of real-world pickle files
- expand the dataset by synthetically generating malicious versions of the real-world files
- run any pickle scanning tool and measure its malicious pickle detection performance

Please note that this benchmark is **experimental** and is intended for use for research purposes only.

## Real-world pickle files
This code scans public ML models. One current culprit is that the benchmark considers all public models to be "safe" by default. This might not be true in practice _depending_ on which files are being downloaded.

**Security warning**: running the benchmark with tools that actually load the downloaded pickle files can be a security risk if the files are not fully trusted.
Make sure the tools being tested only scan the files statically and, when tools don't, run the benchmark in a safe sandboxed environment.

## Requirements
To run this benchmark you'll need to install

## Scripts

### Finding pickle files on HuggingFace
```bash
# Find 20000 files on HuggingFace that are or contain pickle files and store file info and URLs in pickle_files.json
python3 listfiles.py pickle_files.json 20000
```

### Downloading ML/pickle files
```bash
# Download the pickle files specified in pickle_files.json into folder 'dataset'.
# Download 1000 files, discard files above 10MB and below 1KB. Overwrite files in
# the 'dataset' folder if it already exists
python3 download.py pickle_files.json dataset 1000 -m overwrite --maxsize 10000000 --minsize 1000 -e
```

### Injecting malicious payloads in pickle files
```bash
# Inject malicious payloads into files taken from directory `pickle_dataset`.
# Store malicious files in `bad_pickle_dataset`.
# Generate at most 2000 malicious pickle files
python3 inject.py pickle_dataset bad_pickle_dataset 2000
```

### Running pickle scanning analysis
```bash
# Run benchmark on safe & malicious pickle datasets
python3 benchmark.py pickle_dataset bad_pickle_dataset
```

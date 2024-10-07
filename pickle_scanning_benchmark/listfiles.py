import json
import sys
from pathlib import Path
from pprint import pprint
from typing import Optional

from huggingface_hub import HfApi


def hf_get_candidate_files_list(n: int = 100, outfile: Optional[Path] = None):
    """Get a list of pickle files currently hosted on HuggingFace.
    :n: the number of files to get"""
    api = HfApi()
    models = api.list_models(
        # TODO(boyan): more filtering here?
        full=True,  # Get file list
        sort="downloads",  # Get most downloaded models
        direction=-1,
    )
    files = []
    for model in models:
        if model.siblings:
            for s in model.siblings:
                if s.rfilename.endswith((".pkl", ".pt", ".pth", ".bin", "pickle", ".pk")):
                    # TODO(boyan): more filtering here?
                    files.append({"filename": s.rfilename, "project": model.id})
        if len(files) >= n:
            break

    if outfile:
        with open(outfile, "w") as f:
            json.dump(files, f)
    else:
        print("Pickle file URLs")
        pprint(files)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <outfile> <nbfiles>")
        exit(0)
    outfile = sys.argv[1]
    n = int(sys.argv[2])
    hf_get_candidate_files_list(n=n, outfile=outfile)

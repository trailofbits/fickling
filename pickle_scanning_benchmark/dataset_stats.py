import json
from pathlib import Path
from dataclasses import dataclass, field
import os
from fickling.fickle import Pickled
from fickling.pytorch import PyTorchModelWrapper
import sys
import csv
from huggingface_hub import HfApi

api = HfApi()

@dataclass
class Stats:
    nb_files: int = 0
    nb_downloads: int = 0
    projects: dict = field(default_factory=dict)
    file_types: dict = field(default_factory=dict)
    imports: dict = field(default_factory=dict)

    def add(self, file):
        print(f"Adding {file['filename']}")
        if not self._record_imports(file):
            print("\t> File was invalid (no pickles), skipping.")
            return
        self.nb_files += 1
        self._record_project(file["project"])
        self._record_file_type(file)
        

    def _record_file_type(self, file):
        if file["type"] not in self.file_types:
            self.file_types[file["type"]] = 1
        else:
            self.file_types[file["type"]] += 1

    def _record_imports(self, file):
        pickled = self._get_pickled(file)
        if not pickled:
            return False
        for node in pickled.properties.imports:
            for n in node.names:
                import_str = f"{node.module}.{n.name}"
                if import_str in self.imports:
                    self.imports[import_str] += 1
                else:
                    self.imports[import_str] = 1
        return True

    def _get_pickled(self, file):
        try:
            if file["type"] == "pickle":
                with open(file["file"], "rb") as f:
                    return Pickled.load(f)
            elif file["type"] == "pytorch":
                return PyTorchModelWrapper(file["file"]).pickled
        except:
            return None

    def _record_project(self, project):
        # Get downloads
        if project not in self.projects:
            model = api.model_info(project)
            self.projects[project] = model.downloads

    def finalise(self):
        self.imports = dict(sorted(self.imports.items(), key=lambda item: item[1]))

    def dump_imports(self):
        with open("imports.csv", "w", newline="") as f:
            w = csv.DictWriter(f, self.imports.keys())
            w.writeheader()
            w.writerow(self.imports)

    def dump_project_downloads(self):
        with open("downloads.csv", "w", newline="") as f:
            w = csv.DictWriter(f, self.projects.keys())
            w.writeheader()
            w.writerow(self.projects)

def get_stats(dataset_dir: Path):
    with open(dataset_dir / "index.json", "rb") as f:
        index = json.load(f)

    stats = Stats()
    for file in index:
        stats.add(file)
    stats.finalise()
    return stats

if __name__ == "__main__":
    stats = get_stats(Path(sys.argv[1]))
    stats.dump_imports()
    stats.dump_project_downloads()
    print(stats)
    print("Total project downloads", sum(stats.projects.values()))
    print("Avg project download", sum(stats.projects.values()) / len(stats.projects))
    print("Nb projects", len(stats.projects))
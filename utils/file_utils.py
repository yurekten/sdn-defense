import json
import os
import pathlib
import subprocess


def save_dict_to_file(path, file_name, save_object, comparator=None):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)

    file_path = os.path.join(path, file_name)
    if comparator is None:
        comparator = lambda o: o.__str__() if isinstance(o, object) else None

    with open(file_path, 'w') as outfile:
        json.dump(save_object, outfile, default=comparator)
    subprocess.call(['chmod', "-R", '0777', path])

    return file_path
import json
import os
import pathlib
import subprocess


def save_dict_to_file(subpath, file_name, save_object, comparator=None):

    file_path = os.path.join("reports", subpath)
    pathlib.Path(file_path).mkdir(parents=True, exist_ok=True)

    file_name = os.path.join(file_path, file_name)
    if comparator is None:
        comparator = lambda o: o.__str__() if isinstance(o, object) else None

    with open(file_name, 'w') as outfile:
        json.dump(save_object, outfile, default=comparator)
    subprocess.call(['chmod', "-R", '0777', file_name])

    return file_name
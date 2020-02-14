import json
import os
import os.path as path
from typing import Dict, Iterable, Optional, Set, Union


class File:
    @staticmethod
    def deserialize(x: str, o) -> "File":
        return File(x, o["mtime"])

    def __init__(self, name: str, mtime: int):
        self.name = name
        self.mtime = mtime

    def dict(self) -> Dict:
        return {"mtime": self.mtime}

    def __str__(self) -> str:
        return self.name


class Directory:
    @staticmethod
    def deserialize(o) -> "Directory":
        d = Directory(o["name"])
        d.subdirs = {x: Directory.deserialize(o["subdirs"][x]) for x in o["subdirs"]}
        for x in d.subdirs:
            d.subdirs[x].parent = d
        d.files = {x: File.deserialize(x, o["files"][x]) for x in o["files"]}
        return d

    def __init__(self, name: str, parent: Optional["Directory"] = None):
        self.name: str = name
        self.files: Dict[str, File] = {}
        self.subdirs: Dict[str, "Directory"] = {}
        self.parent = parent

    def __contains__(self, item: str):
        return item in self.files or item in self.subdirs

    def __getitem__(self, item: str) -> Union["Directory", File]:
        if item in self.subdirs:
            return self.subdirs[item]
        return self.files[item]

    def __iter__(self) -> Iterable[str]:
        for name in self.subdirs:
            yield name
        for file in self.files:
            yield file

    def path(self) -> str:
        cur = self
        names = []
        while cur is not None and cur.name != "/":
            names.append(cur.name)
            cur = cur.parent
        return "/" + "/".join(reversed(names))

    def dict(self) -> Dict:
        return {"name": self.name, "files": {x: self.files[x].dict() for x in self.files}, "subdirs": {x: self.subdirs[x].dict() for x in self.subdirs}}

    def __str__(self) -> str:
        return self.path()


class Metadata:
    @staticmethod
    def deserialize(s: str) -> "Metadata":
        obj = json.loads(s)
        m = Metadata()
        m.__base = Directory.deserialize(obj["/"])
        return m

    def __init__(self):
        self.__base = Directory("/")

    def __component_iter(self, dir: str) -> Iterable[str]:
        for component in dir[int(dir.startswith("/")):].split("/"):
            if component != "":
                yield component

    def __get_subdir(self, dir: str) -> "Directory":
        cur = self.__base
        for component in self.__component_iter(dir):
            if component not in cur.subdirs:
                return cur
            cur = cur.subdirs[component]
        return cur

    def __get_dir(self, dir: str) -> Optional["Directory"]:
        cur = self.__get_subdir(dir)
        if cur.path() != dir:
            return None
        return cur

    def __make_dir(self, dir: str) -> "Directory":
        cur = self.__get_subdir(dir)
        for component in self.__component_iter(dir[len(cur.path()):]):
            cur.subdirs[component] = Directory(component, cur)
            cur = cur.subdirs[component]
        return cur

    def add(self, filename: str, mtime: Union[float, int, None] = None):
        if not path.isfile(filename):
            raise Exception(f"Only pass files to add(). {filename} is not.")

        filename = path.abspath(filename)
        if mtime is None:
            mtime = path.getmtime(filename)
        mtime = int(mtime)

        cur = self.__make_dir(path.dirname(filename))
        cur.files[path.basename(filename)] = File(path.basename(filename), mtime)

    def dict(self) -> Dict:
        return {"/": self.__base.dict()}

    def __str__(self):
        return json.dumps(self.dict(), sort_keys=True, indent=2)



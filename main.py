from metadata import Metadata
import json

meta = Metadata()
meta.add("/home/jonathan/Documents/compiler_paper.docx")
meta.add("/home/jonathan/classes")
meta.add("/home/jonathan/.cache/xsel.log")
mm = meta.deserialize(str(meta))
print(str(mm))
print(str(mm) == str(meta))
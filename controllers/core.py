#!/usr/bin/env python
# -*- coding=utf-8 -*-
import zipfile
import pathlib

from controllers.taskinfo import TaskInfo

task=None

def try2fail(func):
    def handle_args(*args, **kwargs):
        try:
            return func(*args,**kwargs)
        except Exception:
            return None, None
    return handle_args



def extract_zip(src, target):
    zip_file = zipfile.ZipFile(src)
    zip_file.extractall(path=target)

def find_jar(path):
    found_jars = pathlib.Path(path).glob('**/*.jar')
    return found_jars

def get_name_and_version(path):
    name,version=get_nv_from_filename(path)
    if not name:
        name,version=get_nv_from_jar(path)
    return name,version

def get_name_and_versions(jars):
    ret=[]
    for each_jar in jars:
        name,version=get_name_and_version(each_jar)
        ret.append((str(each_jar),name,version))
    return ret

@try2fail
def get_nv_from_filename(path):
    filename=path.stem
    filenamesplit=filename.split('-')
    return " ".join(filenamesplit[:-1]), filenamesplit[-1]

@try2fail
def get_nv_from_jar(path):
    zip_file = zipfile.ZipFile(str(path))
    name=None
    version=None
    for each_file in zip_file.namelist():
        if each_file.endswith("MANIFEST.MF"):
            with zip_file.open(each_file) as f:
                lines=f.readlines()
                for each_line in lines:
                    each_line=each_line.decode("utf8")
                    if each_line.startswith("Bundle-Name") or \
                        each_line.startswith("Implementation-Title"):
                        name=each_line.rstrip("\r\n").split(": ")[1]
                    if each_line.startswith("Bundle-Version:") or \
                            each_line.startswith("Implementation-Version:"):
                        version=each_line.rstrip("\r\n").split(": ")[1]

    return name, version

    # filename=path.stem
    # filenamesplit=filename.split('-')
    # return "-".join(filenamesplit[:-2]), filenamesplit[-1]



def main(filepath):
    task=TaskInfo(filepath)
    extract_zip(task.zip_path, task.work_path)
    jars=find_jar(task.work_path)
    ret=get_name_and_versions(jars)
    print(ret)

if __name__ == '__main__':
    main("../tests/java-sec-code-1.0.0.war")

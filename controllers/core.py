#!/usr/bin/env python
# -*- coding=utf-8 -*-
import logging
import zipfile
import pathlib
import re
import json
import time
import shutil

from multiprocessing.dummy import Pool    #多线程
from contextlib import closing

from controllers.search import fetch
from controllers.taskinfo import TaskInfo

REPORT=[]

TASK = None

VERSION_PATTERN = re.compile(r'[0-9]+\.{0,1}')


def try2fail(func):
    def handle_args(*args, **kwargs):
        try:
            return func(*args, **kwargs)
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
    name, version = get_nv_from_filename(path)
    if not name:
        name, version = get_nv_from_jar(path)
    return name, version


def get_name_and_versions(jars):
    ret = []
    for each_jar in jars:
        name, version = get_name_and_version(each_jar)
        ret.append((str(each_jar), name, version))
    return ret


@try2fail
def get_nv_from_filename(path):
    filename = path.stem
    filenamesplit = filename.split('-')
    version = VERSION_PATTERN.findall(filenamesplit[-1])
    version = "".join(version)
    return " ".join(filenamesplit[:-1]), version


@try2fail
def get_nv_from_jar(path):
    zip_file = zipfile.ZipFile(str(path))
    name = None
    version = None
    for each_file in zip_file.namelist():
        if each_file.endswith("MANIFEST.MF"):
            with zip_file.open(each_file) as f:
                lines = f.readlines()
                for each_line in lines:
                    each_line = each_line.decode("utf8")
                    if each_line.startswith("Bundle-Name") or \
                            each_line.startswith("Implementation-Title"):
                        name = each_line.rstrip("\r\n").split(": ")[1]
                    if each_line.startswith("Bundle-Version:") or \
                            each_line.startswith("Implementation-Version:"):
                        version = each_line.rstrip("\r\n").split(": ")[1]

    return name, version

    # filename=path.stem
    # filenamesplit=filename.split('-')
    # return "-".join(filenamesplit[:-2]), filenamesplit[-1]


def _format(cve):
    """
    格式化返回格式，符合慕测要求
    :param dic:
    :return:
    """
    str2int={"LOW":1, "MEDIUM":2, "HIGH":3}
    risk_level=str2int[cve["impact"]["baseMetricV2"]["severity"]]
    # 修改一下reference的字段名
    # 修改一个vuln的格式
    if "CVE_data_meta" not in cve:
        cve=cve["cve"]
    if type(cve["description"]["description_data"]) is list:
        description=cve["description"]["description_data"][0]["value"]

    return dict(name=cve["CVE_data_meta"]["ID"],
                updateTime=int(time.time()),
                description=description,
                vulType=0,
                riskLevel=risk_level,
                targetTaskId=0,
                solution="",
                source='cve',
                extra={"category": "Third party libraries",
                       "referenceUrl": cve["references"]["reference_data"],
                      },
                )

def fetch_and_format(each_jar):
    global TASK
    logging.info("Fetching " + " ".join(each_jar))
    cves = fetch(each_jar[1], each_jar[2], TASK.mongodb[0], TASK.mongodb[1])
    for each_cve in cves:
        cve = _format(each_cve)
        cve["vulReferences"]={"location:": each_jar[0], "description":""}
        REPORT.append(cve)

def main(file_path, thread=5, mongodb=('127.0.0.1',27017)):
    global TASK
    TASK = TaskInfo(file_path)
    extract_zip(TASK.zip_path, TASK.work_path)
    jars = find_jar(TASK.work_path)
    jar_list = get_name_and_versions(jars)
    TASK.mongodb=mongodb
    logging.info("Set mongodb = {}".format(mongodb))
    with closing(Pool(processes=thread)) as p:
        p.map(fetch_and_format, jar_list)
    cveids=set()
    cves=[]
    for each in REPORT:
        if each["name"] not in cveids:
            cveids.add(each["name"])
            cves.append(each)
    # for each_jar in jar_list:
    #     logging.info("Fetching " + " ".join(each_jar))
    #     cves = fetch(each_jar[1], each_jar[2])
    #     for each_cve in cves:
    #         cve = _format(each_cve)
    #         cve["vulReferences"]={"location:": each_jar[0],"description":""}
    #         ret.append(cve)
    shutil.rmtree(TASK.work_path)
    return cves


if __name__ == '__main__':
    main("../tests/java-sec-code-1.0.0.war")

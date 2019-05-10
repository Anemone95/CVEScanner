#!/usr/bin/env python
# -*- coding=utf-8 -*-

# https://nvd.nist.gov/vuln/data-feeds#JSON_FEED
import time

from pymongo import MongoClient
import json
import pathlib
import shutil
import os
import _thread as thread

conn = MongoClient('127.0.0.1', 27017)
db = conn.cve
cveitems = db["cveItems"]


def add_one(file):
    with open(file, 'r', encoding="utf-8") as f:
        res = json.load(f)
    result = cveitems.insert(res["CVE_Items"])
    print("Added {0} cves from {1}".format(len(result), file))


def add_all(database):
    jsons = pathlib.Path(database).glob('**/nvdcve*.json')
    for each in jsons:
        add_one(str(each))


if __name__ == '__main__':
    script_path = os.path.split(os.path.realpath(__file__))[0]
    mongodb_path=os.path.join("/tmp/mongodb")
    # mongodb_path=os.path.join(script_path, "mongodb")
    if os.path.exists(mongodb_path):
        shutil.rmtree(mongodb_path)
    os.mkdir(mongodb_path)
    thread.start_new_thread(os.system, ("mongod --dbpath {path} --bind_ip 127.0.0.1".format(path=mongodb_path),))
    add_all(".")
    time.sleep(3)
    # thread.start_new_thread(os.system, ("killall mongod",))
    os.system("killall mongod")
    time.sleep(3)
    print("copy to {}".format(script_path))
    os.system("cd /tmp && tar -czf mongodb.tar.gz mongodb/ && mv -v mongodb.tar.gz {}".format(script_path))
    # add_one(r"D:\Store\document\all_my_work\CZY\CVEScanner\database\nvdcve-1.0-2002.json")

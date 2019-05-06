#!/usr/bin/env python
# -*- coding=utf-8 -*-

# https://nvd.nist.gov/vuln/data-feeds#JSON_FEED

from pymongo import MongoClient
import json
import pathlib

conn = MongoClient('127.0.0.1', 27017)
db = conn.cve
cveitems = db["cveItems"]


def add_one(file):
    with open(file, 'r', encoding="utf-8") as f:
        res = json.load(f)
    result = cveitems.insert(res["CVE_Items"])
    print(result)


def add_all(database):
    jsons = pathlib.Path(database).glob('**/nvdcve*.json')
    for each in jsons:
        add_one(str(each))


if __name__ == '__main__':
    add_all(".")
    # add_one(r"D:\Store\document\all_my_work\CZY\CVEScanner\database\nvdcve-1.0-2002.json")

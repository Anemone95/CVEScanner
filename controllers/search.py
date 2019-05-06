#!/usr/bin/env python
# -*- coding=utf-8 -*-

import requests
import logging
from lxml import etree
from pymongo import MongoClient
import re


def fetch(name, version, ip=None, port=None):
    return fetch_from_mongo(name, version, ip, port)


def fetch_from_mongo(name, version, ip, port):
    conn = MongoClient(ip, port)
    name = name.replace(" ", ".*").replace("_", ".*")
    name = ".*" + name + ".*"
    db = conn.cve
    cveitems = db["cveItems"]
    items = cveitems.find(
        {"cve.affects.vendor.vendor_data.product.product_data.product_name": {'$regex': name}})
    pattern = re.compile(name)
    db = []
    for item in items:
        versions = get_version(item, pattern)
        for each_version in versions["version"]["version_data"]:
            if check(each_version, version):
                db.append(item)
    return db


def get_version(item, pattern):
    for each_vendor in item["cve"]["affects"]["vendor"]["vendor_data"]:
        for each_product in each_vendor["product"]["product_data"]:
            if pattern.search(each_product["product_name"]):
                return each_product


def check(cve_version, version):
    try:
        res = compare(cve_version['version_value'], version)
    except Exception as e:
        print(cve_version)
        raise Exception(e)
    if res in cve_version["version_affected"]:
        return True
    return False


def compare(version1, version2):
    if version1 == version2:
        return "="
    version1 = version1.split(".")
    version2 = version2.split(".")
    for i in range(min(len(version1), len(version2))):
        if version1[i].isdigit() and version2[i].isdigit():
            if version1[i] < version2[i]:
                return "<"
            elif version1[i] > version2[i]:
                return ">"
        elif "*" in version1 or "*" in version2:
            return "="
        elif "-" in version1 or "-" in version2:
            return "="
    if len(version1) != len(version2):
        return "="
    raise Exception("Compare Error: {0} and {1}".format(version1, version2))


def fetch_from_site(name, version):
    """

    :param name: 第三方包名
    :param name: 第三方包版本
    :return: 返回CVE列表
    """

    burp0_url = "https://nvd.nist.gov:443/vuln/search/results?form_type=Basic&results_type=overview&query={}" \
                "&search_type=all".format(name)
    burp0_headers = {"Connection": "close", "Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) "
                                   "Chrome/67.0.3377.1 Safari/537.36",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                     "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"}
    res = requests.get(burp0_url, headers=burp0_headers)
    html_selector = etree.HTML(res.text)
    num = int(html_selector.xpath('//strong[contains(@data-testid,"records-count")]/text()')[0])

    ret = []
    if num == 0:
        return ret

    for i in range(0, num // 20 + 1):
        logging.info("{0} page {1}...".format(name, i))
        burp0_url = "https://nvd.nist.gov:443/vuln/search/results?form_type=Basic" \
                    "&results_type=overview&query={name}" \
                    "&search_type=all&startIndex={idx}".format(name=name, idx=i * 20)
        if i != 1:
            res = requests.get(burp0_url, headers=burp0_headers)
        html_selector = etree.HTML(res.text)
        vulns = html_selector.xpath('//tr[contains(@data-testid,"vuln-row")]/th/strong/a')
        for vuln in vulns:
            vuln_name = vuln.xpath("string(.)")
            vuln_url = vuln.xpath("@href")[0]
            print(vuln_name, vuln_url)
    return ret


if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s', level=logging.INFO)
    print(fetch("tomcat", "1.2.24"))
    # print(compare("1.3.3.a", "1.3.3.1"))

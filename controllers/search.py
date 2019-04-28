#!/usr/bin/env python
# -*- coding=utf-8 -*-

import requests
from lxml import etree


def fetch(name, version):
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

    if num == 0:
        return []

    vulns=html_selector.xpath('//tr[contains(@data-testid,"vuln-row")]/th/strong/a')
    print(vulns.xpath(""))
    return [{}]


if __name__ == '__main__':
    fetch("fastjson", "1.2.24")

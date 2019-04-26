#!/usr/bin/env python
# -*- coding=utf-8 -*-
import os

class TaskInfo(object):
    def __init__(self, zip_path=None):
        self.__work_path = None
        self.__zip_path = None
        self.tool_path = os.path.join(os.path.split(os.path.realpath(__file__))[0], '..')
        if zip_path:
            self.__zip_path=os.path.abspath(zip_path)
            self.__work_path=os.path.abspath(".".join(self.zip_path.split('.')[:-1]))

    @property
    def work_path(self):
        return self.__work_path

    @work_path.setter
    def work_path_setter(self, path):
        self.__work_path = os.path.abspath(path)

    @property
    def zip_path(self):
        return self.__zip_path

    @work_path.setter
    def zip_path_setter(self, path):
        self.__zip_path = os.path.abspath(path)


if __name__ == '__main__':
    t=TaskInfo("..\\tests\\java-sec-code-1.0.0.war")
    print(t.zip_path)
    print(t.tool_path)
    print(t.work_path)
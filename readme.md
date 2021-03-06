# 简介
CVEScanner是一扫描项目中使用不安全组件的工具，其首先收集nvd数据库中的CVE，接着给定项目（jar/war包），其会通过版本匹配的方式发现其是否含有存在漏洞的第三方组件。

# 安装(Docker)
## 构建镜像

1. 下载最新数据到database目录下，下载地址：https://nvd.nist.gov/vuln/data-feeds#JSON_FEED

2. 如果没有数据库生成docker，需要先构建数据库生成docker，否则跳第3步

   ```bash
   $ cd database
   $ docker build . -t anemone/cvedbmaker
   ```

3. 运行容器生成数据库，需要挂载database到/workspace，若database下出现mongodb.tar.gz，则数据库制作成功

   ```bash
   $ docker run --name "tmp" -i -v /mnt/d/Store/document/all_my_work/CZY/CVEScanner/database:/workspace anemone/cvescanner
   ...
   Added 14322 cves from nvdcve-1.0-2018.json
   Added 2798 cves from nvdcve-1.0-2019.json
   copy to /workspace
   ```

4. 构建镜像：

   ```bash
   $ docker build . -t anemone/cvescanner
   ```


## 容器使用

挂载被扫描包所在目录，并执行start命令：

```bash
docker run --name "test" -i -v /mnt/d/Store/document/all_my_work/CZY/CVEScanner/tests:/workspace anemone/cvescanner "start -F java-sec-code-1.0.0.war"
```


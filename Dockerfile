FROM alpine:latest

# 镜像描述
LABEL \
    name="CVEScanner" \
    author="Anemone <x565178035@126.com>" \
    maintainer="Anemone <x565178035@126.com>" \
    contributor="Anemone <x565178035@126.com>"  \
    description="A CLI version of CVEScanner."

# 修改更新源
#RUN echo 'http://dl-cdn.alpinelinux.org/alpine/v3.6/main' >> /etc/apk/repositories
#RUN echo 'http://dl-cdn.alpinelinux.org/alpine/v3.6/community' >> /etc/apk/repositories
RUN echo 'https://mirror.tuna.tsinghua.edu.cn/alpine/v3.6/main' > /etc/apk/repositories
RUN echo 'https://mirror.tuna.tsinghua.edu.cn/alpine/v3.6/community' >> /etc/apk/repositories

# 安装python和pip install需要的环境
RUN apk add --update \
    bash \
    mongodb=3.4.4-r0 \
    python3 \
    python3-dev \
    py3-pip \
    build-base \
    libffi-dev \
    openssl-dev \
    libxml2-dev \
    libxslt-dev \
  && rm -rf /var/cache/apk/*

ADD ./database/mongodb.tar.gz /mongodb/
# 复制项目，将项目文件复制到docker中
COPY . /CVEScanner
ENV PATH="/CVScanner:${PATH}"

# 安装项目的依赖
WORKDIR /CVEScanner
RUN pip3 install -r requirements.txt -i http://pypi.douban.com/simple --trusted-host pypi.douban.com --no-cache-dir

# 提供启动命令，用户输入的命令会接在ENTRYPOINT命令后面
WORKDIR /workspace
# docker run --name "test" -i -v /mnt/d/Store/document/all_my_work/CZY/CVEScanner/tests:/workspace anemone/cvescanner "start -F java-sec-code-1.0.0.war --mongodb=192.168.70.1:27017"
ENTRYPOINT ["sh", "/CVEScanner/mt_cvescanner"]

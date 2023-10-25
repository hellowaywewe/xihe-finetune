FROM openeuler/openeuler:23.03 as BUILDER
RUN dnf update -y && \
    dnf install -y golang && \
    go env -w GOPROXY=https://goproxy.cn,direct

MAINTAINER zengchen1024<chenzeng765@gmail.com>

# build binary
COPY . /go/src/github.com/opensourceways/xihe-finetune
RUN cd /go/src/github.com/opensourceways/xihe-finetune && GO111MODULE=on CGO_ENABLED=0 go build -o xihe-finetune -buildmode=pie --ldflags "-s -linkmode 'external' -extldflags '-Wl,-z,now'"

# copy binary config and utils
FROM openeuler/openeuler:22.03
RUN dnf -y update && \
    dnf in -y shadow git bash && \
    groupadd -g 5000 mindspore && \
    useradd -u 5000 -g mindspore -s /bin/bash -m mindspore

USER mindspore
WORKDIR /opt/app

COPY --chown=mindspore --from=BUILDER /go/src/github.com/opensourceways/xihe-finetune/xihe-finetune /opt/app
RUN chmod 550 /opt/app/xihe-finetune

ENTRYPOINT ["/opt/app/xihe-finetune"]


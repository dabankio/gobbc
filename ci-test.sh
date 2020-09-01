#!/bin/bash

export GOPROXY=https://goproxy.cn
go test . && cd qa && go test -v --short .
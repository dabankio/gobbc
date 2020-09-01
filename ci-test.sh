#!/bin/bash

go test . && cd qa && go test -v --short .
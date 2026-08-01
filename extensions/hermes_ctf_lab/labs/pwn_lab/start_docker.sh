#!/bin/bash
cd "$(dirname "$0")"
docker compose build
# 把编译好的 ELF 拷回任务目录，供 agent 静态 triage（rev）
docker create --name pwnlab_x hermes-pwnlab >/dev/null 2>&1
docker cp pwnlab_x:/vuln ./vuln >/dev/null 2>&1
docker rm pwnlab_x >/dev/null 2>&1
docker compose up -d

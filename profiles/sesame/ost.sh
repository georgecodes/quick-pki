#!/usr/bin/env bash

openssl req -new \
  -newkey rsa:2048 \
  -nodes \
  -keyout transport.key \
  -out transport.csr \
  -config transport-csr.cnf
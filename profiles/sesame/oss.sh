#!/usr/bin/env bash

openssl req -new \
  -newkey rsa:2048 \
  -nodes \
  -keyout signing.key \
  -out signing.csr \
  -config signing-csr.cnf
# Quick Start

## Introduction

This quick start shows how to simply deploy an Autha instance.

## Understanding your needs

Autha is primarily designed for Gravitalia. However, there's nothing to stop you using it for your own projects.


You are required to use **Apache Cassandra** (or ScyllaDB). However, you are free to use other databases, such as:
- Memcached (entirely optional);
- Apache Kafka OR RabbitMQ (entirely optional).

Memcached is used to perform global cached actions, while Apache Kafka (or RabbitMQ) is used to emit event messages for others services, which is probably not the case for you.

## Deploy simple Autha instance
> You'll need to install [Docker](https://www.docker.com/).

1. Create a `config.yaml` file.
   Create a configuration file named `config.yaml` and then, write:
  ```yaml
  port: 1111 # HTTP API port.

  database:
    scylla:
      username: cassandra
      password: cassandra
      hosts:
        - scylla:9042
      pool_size: 3
   ```

  You can see more paramters on [/config.yaml](https://github.com/Gravitalia/Autha/blob/master/config.yaml).

2. Create a `docker-compose.yaml` file.
  Write
  ```yaml
  version: '3.9'

services:
  autha:
    image: ghcr.io/gravitalia/autha:3.0.0
    platform: linux/amd64
    container_name: autha
    restart: always
    ports:
      - 1111:1111
    depends_on:
      - cassandra
    volumes:
      - ./config.yaml:/config.yaml

  cassandra:
    image: cassandra:latest
    restart: always
    container_name: cassandra
    ports:
      - 9042:9042
    volumes:
      - ./data/cassandra:/var/lib/cassandra
  ```

  3. Execute `docker-compose up`.

## To go further...

You can take a look at our example [docker-compose.yaml](https://github.com/Gravitalia/Autha/blob/master/docker-compose.yml) and [config.yaml](https://github.com/Gravitalia/Autha/blob/master/config.yaml) files.

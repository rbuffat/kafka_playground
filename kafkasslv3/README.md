# Zookeeper with TLS Quorum

## Configuration

Zookeeper servers: `ZOO_SERVERS: kafkasslv3-zookeeper-1.kafka:2888:3888,kafkasslv3-zookeeper2-1.kafka:2888:3888,kafkasslv3-zookeeper3-1.kafka:2888:3888`

SSL Certificates:

- Common Name: kafkasslv3-zookeeper-1.kafka # respectively kafkasslv3-zookeeper2-1.kafka, zookeeper3
- Subject Alternative Name: DNS: kafkasslv3-zookeeper-1.kafka # respectively kafkasslv3-zookeeper2-1.kafka, kafkasslv3-zookeeper3-1.kafka

## Steps

Start zookeeper ensemble using:

`docker-compose up zookeeper zookeeper2 zookeeper3`

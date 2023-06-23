# Introduction
This repository contains implementation of spring boot admin and client. Spring Boot Admin can be used to perform monitoring activities on spring boot applications. This repo contains two modules:

1- admin-server - This module has code for spring boot admin.
2- admin-client - This module has code for a spring boot application which is a client that registers itself with spring boot admin.

As a sample client exposes loggers endpoint via actuator and once client registers itself with server, log level of the client can be changed dynamically.
Admin module has been secured using spring security basic authentication. The basic credentials are mentioned in admin-server modules *application.yml*

# Running the modules

**admin-server** - Firstly, run the admin server via AdminServer.java
**admin-client** - Secondly, run the admin client via AdminClient.java

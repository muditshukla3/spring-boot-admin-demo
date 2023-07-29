# Introduction
This repository contains implementation of spring boot admin and client. Spring Boot Admin can be used to perform monitoring activities on spring boot applications. This repo contains two modules:

1- admin-server - This module has code for spring boot admin. Access the spring boot admin via http://localhost:8080

2- admin-client - This module has code for a spring boot application which is a client that registers itself with spring boot admin. This module exposes one endpoint http://localhost:8081/log which just prints different log statements based on the log level set for the application.

As a sample, client exposes loggers endpoint via actuator and once client registers itself with server, log level of the client can be changed dynamically.
Admin module has been secured using spring security ldap authentication. The basic credentials are mentioned in admin-client modules *application.yml*

During startup of admin-server module, an embedded ldap server also starts up on port 8389.
## Running the modules

*admin-server* - First, run the admin server via AdminServer.java

*admin-client* - Secondly, run the admin client via AdminClient.java

## Reference
Spring security ldap authentication implementation reference has been taken from Spring's Getting Started Guide "Authenticating a User with LDAP" and integrated with Spring Boot Admin's security configuration. 

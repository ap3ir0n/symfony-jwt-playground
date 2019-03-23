This is a demo app showing how to configure Symfony framework for JWT authentication through LexikJWTAuthenticationBundle. JWT are used for both REST API and old fashioned controllers. Uniforming the authentication method will help you to easily manage authentication on frontend side. In addition using JWT will allow you to create true stateless REST API.

Installation instructions
-------------------------

1. composer install
2. mkdir config/jwt
3. openssl genrsa -out config/jwt/private.pem -aes256 4096
4. openssl rsa -pubout -in config/jwt/private.pem -out config/jwt/public.pem
5. Create your .env.local and set the JWT_PASSPHRASE

Usage
-----

1. php bin/console server:run
2. Navigate across the various routes 

Routes
------

Routes are defined in config/routes.yaml. Login can be performed in 2 different ways:
1. login form at http://localhost:8000/web/login
2. login REST API at http://localhost:8000/api/login 

You can test getting the token with a simple curl command like this (adapt host and port):
```bash
curl -X POST -H "Content-Type: application/json" http://localhost:8000/api/login -d '{"username":"john_admin","password":"sicura"}'
```

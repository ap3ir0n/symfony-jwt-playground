Installation instructions
-------------------------

1. composer install
2. mkdir config/jwt
3. openssl genrsa -out config/jwt/private.pem -aes256 4096
4. openssl rsa -pubout -in config/jwt/private.pem -out config/jwt/public.pem
5. create yoyr .env.local and set the jwt secret key

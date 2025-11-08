# Database

Autha uses PostgreSQL as database. Database handles account management
(including public keys and refresh tokens) and invitations.

Add in `config.yaml` following code:
```yaml
postgres:
  address: postgres:5432
  database: autha
  username: postgres
  password: postgres
  pool_size: 25
  ssl: false
```

| Parameter              | Description                                               |
|------------------------|-----------------------------------------------------------|
| `address`              | URL of Postgres database.                                 |
| `database`             | Database name on Postgres.                                |
| `username`             | Postgres' username.                                       |
| `password`             | Postgres' password.                                       |
| `pool_size`            | Maximum number of concurrent connections to database.     |
| `ssl`                  | Wether allow or not secure connection.                    |

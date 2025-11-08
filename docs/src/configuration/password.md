# Password

Autha uses Argon2 to hash users's passwords.
Only change the settings if you know what you are doing.

Add in `config.yaml` following code:
```yaml
argon2:
  memory_cost: 65536 # 64 MiB.
  iterations: 4
  parallelism: 2
  hash_length: 32
  zxcvbn: 3
```

| Parameter              | Description                                               |
|------------------------|-----------------------------------------------------------|
| `memory_cost`          | Memory cost of a hash in KiB.                             |
| `iterations`           | Number of iterations.                                     |
| `parallelism`          | Parallelism degree.                                       |
| `hash_length`          | Password hash result length. Higher avoid collisions.     |
| `zxcvbn`               | Optional. Dropbox password strength metering.             |

# Time-based One-Time Password (TOTP)

This extension cannot be disabled.
It provides users with additional security (a period-second symmetric token).

Add in `config.yaml` following code:
```yaml
totp:
  issuer: autha
  algorithm: sha1
  digits: 6
  period: 30 # in seconds
```

| Parameter     | Description                                               |
|---------------|-----------------------------------------------------------|
| `issuer`      | Name displayed on the user authentication application.    |
| `algorithm`   | MUST be `sha1`.                                           |
| `digits`      | Number of digits for the 30-second token.                 |
| `period`      | Token time window.                                        |

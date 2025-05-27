# LDAP

Autha supports LDAP directory integration for user and group resolution. This feature enables compatibility with enterprise identity systems by dynamically resolving user attributes and group memberships through LDAP queries.

Add in `config.yaml` following code:
```yaml
ldap:
  address: ldap://127.0.0.1:389
  user: CN=admin,DC=domain,DC=local
  password: admin
  base_dn: DC=domain,DC=local
  additional_users_dn: OU=users
  users_filter: '(&(uid={user_id}))'
  additional_groups_dn: 'OU=groups'
  groups_filter: '(&(member={dn})(objectClass=groupOfNames))'
```

| Parameter              | Description                                               |
|------------------------|-----------------------------------------------------------|
| `address`              | URL of the LDAP server. Support `ldap://` and `ldaps://`. |
| `user`*                | DN of admin LDAP account used to create new entries.      |
| `password`*            | `userPassword` for admin account.                         |
| `base_dn`              | Root DN for all LDAP searches.                            |
| `additional_users_dn`  | Sub-path under `base_dn` to locate user entries.          |
| `users_filter`         | LDAP filter to find a specific user                       |
| `additional_groups_dn`,| Sub-path under `base_dn` to locate group entries.         |
| `groups_filter`        | LDAP filter to find groups containing the user            |

\* You can omit `user` and `password` field if you don't want to create new entires on LDAP via Autha.
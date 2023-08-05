# pistol_cli-rs

Pure rust nmap-like scan tool.

# Port scan example

```bash
pistolcli --scan --syn --host 192.168.72.136 --port 80 -i ens33
```

## Ping example

```bash
pistolcli --ping --syn --host 192.168.72.135 -i ens33
```
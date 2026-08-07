### 防火墙
```powershell
$Name="名称"; $Port="端口"; Remove-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue; "TCP","UDP" | ForEach-Object { New-NetFirewallRule -DisplayName $Name -Direction Inbound -Protocol $_ -LocalPort $Port -Action Allow -Profile Private,Public -RemoteAddress ::/0 }
```


```bash
NAME="名称" && PORT="端口" && (uci -q delete firewall.$NAME; uci commit firewall) && uci add firewall rule > /dev/null && uci set firewall.@rule[-1].name="$NAME" && uci set firewall.@rule[-1].src="wan" && uci set firewall.@rule[-1].dest="lan" && uci set firewall.@rule[-1].family="ipv6" && uci set firewall.@rule[-1].dest_port="$PORT" && uci set firewall.@rule[-1].target="ACCEPT" && uci commit firewall && service firewall reload
```

### Windows 11 最新版-简体中文 64 位 ISO 镜像
```powershell
& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/pbatard/Fido/master/Fido.ps1').Substring(3))) -Win 11 -Rel Latest -Lang Simplified -Arch x64 -GetUrl
```

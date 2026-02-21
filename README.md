## WireGuard Tunneling via TURN Servers

Forward WireGuard/Hysteria traffic through VK calls or Yandex Telemost TURN servers. Packets are encrypted with DTLS 1.2, then sent via parallel TCP or UDP streams to the TURN server using the STUN ChannelData protocol. From there, they are forwarded via UDP to your server, where they are decrypted and passed to WireGuard. TURN login/password are generated from the call link.

## Configuration
You will need:
1. An active VK call link: create your own (requires a VK account), or search for `"https://vk.com/call/join/"`.
   The link remains valid forever unless you click "end call for all".
2. Or a Yandex Telemost call link: `"https://telemost.yandex.ru/"`. It should look like this: `https://telemost.yandex.ru/j/12345678901234`. It's better not to search for this publicly, as conference connections are visible.
3. A VPS with WireGuard installed.
4. For Android: download Termux from F-Droid. Or use ADB I dont know.

### Server
```
./server -listen 0.0.0.0:56000 -connect 127.0.0.1:<wg port>
```

### Client
#### Android
- In the WireGuard client config, change the server address to `127.0.0.1:9000`, set MTU to 1280.
- **Add Termux to WireGuard exclusions. Click "Save".**
In Termux:
```
termux-wake-lock
```
Your phone won't enter deep sleep, so charge it overnight. To disable:
```
termux-wake-unlock
```
Copy the binary to a local folder, grant execute permissions:
```
cp /sdcard/Download/client-android ./
chmod 777 ./client-android
```
Run:
```
./client-android -peer <server wg ip>:56000 -vk-link <VK link> -listen 127.0.0.1:9000
```
Or
```
./client-android -udp -turn 5.255.211.241 -peer <server wg ip>:56000 -yandex-link <Ya link> -listen 127.0.0.1:9000
```

**If DNS errors appear in the terminal after enabling VPN, try enabling VPN only for specific apps in WireGuard.**
#### Linux
In the WireGuard client config, change the server address to `127.0.0.1:9000`, set MTU to 1280.

The script will add routes to necessary IPs:

```
./client-linux -peer vps_ip_here:56000 -vk-link vk_link_here -listen 127.0.0.1:9000 | sudo routes.sh
```

```
./client-linux -udp -turn 5.255.211.241 -peer vps_ip_here:56000 -yandex-link yandex_link_here -listen 127.0.0.1:9000 | sudo routes.sh
```

Do not enable the VPN until the program establishes a connection! Unlike Android, some requests (DNS and TURN connection) will go through the VPN here.
#### Windows
In the WireGuard client config, change the server address to `127.0.0.1:9000`, set MTU to 1280.

In PowerShell as Administrator (so the script can add routes):

```
./client.exe -peer vps_ip_here:56000 -vk-link vk_link_here -listen 127.0.0.1:9000 | routes.ps1
```

```
./client.exe -udp -turn 5.255.211.241 -peer vps_ip_here:56000 -yandex-link yandex_link_here -listen 127.0.0.1:9000 | routes.ps1
```

Do not enable the VPN until the program establishes a connection! Unlike Android, some requests (DNS and TURN connection) will go through the VPN here.

### Troubleshooting
Use the `-turn` option to manually specify the TURN server address. This should be a VK, Mail.ru/Max, Odnoklassniki server (for VK links) or Yandex server (for Yandex links).

If TCP doesn't work, try adding the `-udp` flag.

Add the `-n 1` flag for a more stable single‑stream connection (5 Mbps limit for VK).

## Yandex Telemost
Unlike VK, Yandex servers do not limit speed, so `-n 1` is set by default. Increasing this number may lead to temporary IP blocking due to flooding the conference with fake participants.

In `-udp` mode, speed is usually higher.

Most Yandex TURN server IP ranges don't work; specify manually via `-turn`.

<details>
<summary>Working IPs</summary>

```
5.255.211.241
5.255.211.242
5.255.211.243
5.255.211.245
5.255.211.246
```
</details>

Thanks to https://github.com/KillTheCensorship/Turnel for part of the code :)

## v2ray
Instead of WireGuard, you can use any V2Ray‑core that supports it (e.g., xray or sing‑box) and any V2Ray client that uses that core (e.g., v2rayN or v2rayNG). With them you can add more inbound interfaces (e.g., SOCKS) and implement fine‑grained routing.

Example configs:

<details>
<summary>Client</summary>

```json
{
    "inbounds": [
        {
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": 1080,
            "settings": {
                "udp": true
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        },
        {
            "protocol": "http",
            "listen": "127.0.0.1",
            "port": 8080,
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "wireguard",
            "settings": {
                "secretKey": "client_secret_key_here",
                "peers": [
                    {
                        "endpoint": "127.0.0.1:9000",
                        "publicKey": "server_public_key"
                    }
                ],
                "domainStrategy": "ForceIPv4",
                "mtu": 1280
            }
        }
    ]
}
```
</details>

<details>
<summary>Server</summary>

```json
{
    "inbounds": [
        {
            "protocol": "wireguard",
            "listen": "0.0.0.0",
            "port": 51820,
            "settings": {
                "secretKey": "server_secret_key_here",
                "peers": [
                    {
                        "publicKey": "client_public_key_here"
                    }
                ],
                "mtu": 1280
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "UseIPv4"
            }
        }
    ]
}
```
</details>

## Direct mode
With the `-no-dtls` flag you can send packets without DTLS obfuscation and connect to regular WireGuard servers. May lead to blocking by VK/Yandex.

* Download binary's [here](https://github.com/AbikusSudo/Apisc/releases)
* Source code [here](https://github.com/AbikusSudo/Apisc)
* Contact with me [here](https://t.me/AbikusSudo)
* Programming with me here :>
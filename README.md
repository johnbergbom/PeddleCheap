# PeddleCheap
Pcaps for PeddleCheap and implant communication + script for interpreting pcaps.

Decryptor script:  
dp_decrypt.py: script to decrypt (and verbosely explain) the traffic when HTTP Proxy is used

Pcap files:  
forward_level3_tcp_port_1163.pcap: level3 standard tcp implant with PeddleCheap doing a forward connection to implant  
forward_level4_tcp_port_1167.pcap: level4 standard tcp implant with PeddleCheap doing a forward connection to implant  
reverse_level3_http_port_80.pcap: level3 http proxy implant with implant doing reverse connection to PeddleCheap  
reverse_level3_http_port_443.pcap: level3 http proxy implant with implant doing reverse connection to PeddleCheap  
reverse_level3_tcp_port_53.pcap: level3 standard tcp implant with implant doing reverse connection to PeddleCheap  

Supporting files:
00041-pc_listen_2017_10_16_09h37m12s.966.xml: DanderSpritz log file (corresponds to reverse_level3_http_port_80.pcap)  
successful_reverse_connection_port80.txt: another DanderSpritz log file (corresponds to reverse_level3_http_port_80.pcap)  
Dsz_Implant_Pc.dll: PeddleCheap uploads this file to have it executed by the implant  
DszLpCore.exe: executable that listens to open ports on the DanderSpritz host  
PeddleCheap_Lp.dll: imported by DszLpCore.exe, communicates with the implant  
PeddleCheap_2017_10_16_09h32m09s.409: directory containing implant (for reverse_level3_http_port_80.pcap) as well as the default public/private keys  

Sample output when ran against reverse_level3_http_port_80.pcap:
----------------------------------------------------------------
$ python dp_decrypt.py reverse_level3_http_port_80.pcap out.file PeddleCheap_2017_10_16_09h32m09s.409/Keys/private_key.bin

Searching in pcap for implant deployment to DoublePulsar:  
Nbr packets: 1355  
packet nbr 13 (ping request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 14 response: success  
  packet nbr 14 xor key in response: 0x75503953 , target arch: x64 (64-bit)  
packet nbr 15 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
packet nbr 15: xor key for encrypting payload to DoublePulsar: 0x75503953  
  packet nbr 19 response: success  
packet nbr 20 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 24 response: success  
packet nbr 25 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 29 response: success  
packet nbr 30 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 34 response: success  
packet nbr 35 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 39 response: success  
packet nbr 40 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 44 response: success  
packet nbr 45 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 49 response: success  
packet nbr 50 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 54 response: success  
packet nbr 55 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 59 response: success  
packet nbr 60 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 64 response: success  
packet nbr 65 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 69 response: success  
packet nbr 70 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 74 response: success  
packet nbr 75 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 79 response: success  
packet nbr 80 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 84 response: success  
packet nbr 85 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 89 response: success  
packet nbr 90 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 94 response: success  
packet nbr 95 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 99 response: success  
packet nbr 100 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 104 response: success  
packet nbr 105 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 109 response: success  
packet nbr 110 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 114 response: success  
packet nbr 115 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 119 response: success  
packet nbr 120 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 124 response: success  
packet nbr 125 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 129 response: success  
packet nbr 130 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 134 response: success  
packet nbr 135 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 139 response: success  
packet nbr 140 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 144 response: success  
packet nbr 145 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 149 response: success  
packet nbr 150 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 154 response: success  
packet nbr 155 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 159 response: success  
packet nbr 160 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 164 response: success  
packet nbr 165 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 169 response: success  
packet nbr 170 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 174 response: success  
packet nbr 175 (exec request): 10.0.0.2:1892 -> 10.0.0.10:445  
  packet nbr 178 response: success  
DoublePulsar payload written to out.file

Extracting public key data from pcap:  
Public key written to out.file.public_key  
Key length: 2048  
Modulus: 0x9c49002465e0ee9ea5df71a77ffb33ac8681125d3e740bfa75c00503ad5482874e41a774348d5fac28841135536d8a5286121eb02d19712173fbb81ba8e0b27c58e303e6723aa7975e24c999c211dbc72f5066382a79c3b2a86a6386fe98f36d541dacd1a08f237af8635d20d06074df7ab363125e7202be6326fd9ba1ca4e861ff224e65d3eeffab9f3c17756b1c43217835a511923c02fb2c0dbf6f669933d5a495b1a27b7cb86c3ee14c6890b97dc3610fd89dc096bdd09e6f07dbd4ee592b46020b0fab89cf4dfdc567eb653317f37ec66158433faf5f6fc1fb70ed2cbcf862a0f3b30317034366d1f7b95f8148cae663596e7ec823041c52253eec53ae1  
Public key exponent: 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001  

Extracting private key data from provided file:  
Private key exponent: 0x2c28401f089e0e2dcb262001b89a6c5641c6b43e9e47c19ea9a8708242760f4f55a01d452b180ac124cd73e342483ffde31db98803a61d9ddb1c733f756ecf5f6ce9ef8f2c154086f735a3b48aedead013a13ed07dc7dbb05dff79518a1c03238fd1b6a3a01ef1626c4dfee1279f29467f6fb1fd5dac0ef466257d207d0d2134393bfb7caf65b2ab1a122b561b594af4fe676cf271ef6ddd4cd60294556caff6ac48411b31518585a3ce9406445214925152c640a6d3acbcec8aec639ebb7039faf1d659c9eb4eef9462fc8e8924338da2c9ff867a3c316228d89e45da360f4af0e504f3e2ca6de32f42a2ef3426a840ce7d67b7ad91dd99367e413a4c59c771  
Prime 1: 0xcdf9397a78e918aa4319cc5c3271e51f47565ce487b0f66cfbd7997bc57460729258640da0eef9a876e363d4b865488e5f168afec04693304e15797e06661ec554a68a09c68809f82e6695db4242c44e6418edad6c40388151e23a5a686906fe2337c95e2cddac42af0e79f93d9da3c0cc9786c2f4dcada901b1111ba47f80a5  
Prime 2: 0xc23e4fd2fcd07816ed7b2aacb26bf111e1c4f371b2ebb826b02c8e00cfa4744a65be0aaca83b3d22a5d9f5bd97bd97c18ebd9f69f4657dc42649a5cda35fa1bebe9bffa578d487475bb8f50e6191dc950371e361012c44a7e7c4dea674abea452b5eb1141c156b22dad5a3024f33f5ad5c1675cc506346c02029dc0a701fe08d  
Prime exponent 1: 0x1294a0f2c36583ac18518375edb7088c41cb30a60cf791c35314a7ebda6c1d2738bc708a2a3264a325d66d730b0f57f43fefb0aa3a7e235900323fbb76a84fae4d6c989739299c7c9ef2f221cd60688509d295de471da3fb467fb9f3dde75b92216b2ee727f4f74d2cad89a34a43a63a063ac515613167190fe6013d1521cb61  
Prime exponent 2: 0x3a81c2516eccec1f1bd0e97db3104840769c78275b191d12aa26016fc51b67dbb0e1991d805eb77f642d4e9398cd0694ca85db2a72eecefef1f964f397ae0a6e05c3bf30fc4027af1ab58f3a91b0f99bf8b9a91f62d70ea6f46c9c13cf38a90bc490750df5978df9a5a88bbcfa56503db36b2078360e7115159b06282eb5ab51  
Coefficient: 0x2c8bd71480d4b5bfa368551f27b776d99b69c040eefaa78d7d99020ec1fa471d9bddc705273a2e20897b4f2346d90f0537318504f09f6d2a528cba87c4c1ff44d3cd4b361d51ac03f16047136f30e6b0f5012f8253ea3d62d8bea222b318dc669a8f4713f9888bfc02bfbe9c7c5ae6817b84ec24a10f9a47df19263ba3b4b530  

Analyzing traffic between implant and DanderSpritz:  
packet nbr 200: initial contact from implant to DanderSpritz  
  Seq nbr: 0  
  Payload length: 0  
  Clear text length: 0  
  Symm. encr. used: 0  
  Custom header: TlEo: 0e59a2bc9:00000000  
packet nbr 203: contains response from DanderSpritz (digital signature / magic number)  
  Seq nbr: 1  
  Payload length: 256  
  Clear text length: 256  
  Symm. encr. used: 0  
  Decrypted magic number: 0x1fffffff...ffff00000200038e3071abdc7d00b9  
  => interpretation:  
  PeddleCheap ver: 2.3.0  
  Magic number: 8e3071ab  
  Random padding: dc7d  
  Nbr random bytes: 185  
packet nbr 211: implant sends symmetric key and platform info to DanderSpritz  
  Seq nbr: 1  
  Payload length: 256  
  Clear text length: 256  
  Symm. encr. used: 0  
  Decrypted data: 000200031f0000009ac96bc2ca877c5394f1e5dcf009d07e000000000000000000000008000000080000000100000001  
  => interpretation:  
  Implant ver: 2.3.0  
  Session key: 0x9ac96bc2ca877c5394f1e5dcf009d07e  
  PC ID: 0000000000000000  
  Architecture: 0008 (x64)  
  Compiled architecture: 0008 (x64)  
  Platform: 0001 (winnt)  
  Compiled platform: 0001 (winnt)  
  Next IV: b5f5546662b92c858cca6ac04c530a94  
packet nbr 214: DanderSpritz response after getting magic number  
  Seq nbr: 2  
  Payload length: 16  
  Clear text length: 4  
  Symm. encr. used: 1  
  Decrypted data (OS version check status): 0x00000000  
  Next IV: 82413a117e459d08824cdd2ca9380ea2  
packet nbr 222: implant acknowledges reception of OS version check status  
  Seq nbr: 2  
  Payload length: 16  
  Clear text length: 4  
  Symm. encr. used: 1  
  Decrypted data (OS version check reception acknowledgement): 0x00000000  
  Next IV: 4d801fbdc6bb391d5c6f8f1efd77049d  
packet nbr 225: DanderSpritz empty response  
  Seq nbr: 3  
  Payload length: 0  
  Clear text length: 0  
  Symm. encr. used: 0  
packet nbr 233: implant asks for new command from DS  
  Seq nbr: 3  
  Payload length: 0  
  Clear text length: 0  
  Symm. encr. used: 0  
packet nbr 236: DanderSpritz sends PayloadInfo run type info and File/Library info to implant  
  Seq nbr: 4  
  Payload length: 16  
  Clear text length: 4  
  Symm. encr. used: 1  
  Decrypted data (PayloadInfo run type info): 0x00020000  
  Next IV: bdf117e78479cc2c36abd53e365c10ba  
  Payload length: 48  
  Clear text length: 36  
  Symm. encr. used: 1  
  Decrypted data (File/Library info): 0x0000000000000001000000000000000100000003dcce000000028af4205d000200080000  
  Next IV: 37df8c4f8464e08ec7334fe68167d5c1  
packet nbr 244: implant acknowledges reception of File/Library info  
  Seq nbr: 4  
  Payload length: 16  
  Clear text length: 4  
  Symm. encr. used: 1  
  Decrypted data (File/Library info reception acknowledgement): 0x00000000  
  Next IV: ad55f14210e59f5663c5086b0cfa6cba  
packet nbr 247: DanderSpritz sends Export name to implant  
  Seq nbr: 5  
  Payload length: 16  
  Clear text length: 3  
  Symm. encr. used: 1  
  Decrypted data (Export name): 0x233100  
  Next IV: 4209181c23ee7273dd702f52ba699941  
packet nbr 255: implant acknowledges reception of Export name  
  Seq nbr: 5  
  Payload length: 16  
  Clear text length: 4  
  Symm. encr. used: 1  
  Decrypted data (Export name reception acknowledgement): 0x00000000  
  Next IV: 4eff69ab69ab6048822d22e590d54d1f  
packet nbr 258: DanderSpritz sends executable to implant  
  Seq nbr: 6  
  Payload length: 166656  
  Size of executable: 166644  
  Symm. encr. used: 1  
packet nbr 282: DanderSpritz sends executable to implant  
packet nbr 306: DanderSpritz sends executable to implant  
packet nbr 331: DanderSpritz sends executable to implant  
packet nbr 359: DanderSpritz sends executable to implant  
packet nbr 384: DanderSpritz sends executable to implant  
packet nbr 408: DanderSpritz sends executable to implant  
packet nbr 433: DanderSpritz sends executable to implant  
packet nbr 457: DanderSpritz sends executable to implant  
packet nbr 481: DanderSpritz sends executable to implant  
packet nbr 506: DanderSpritz sends executable to implant  
packet nbr 530: DanderSpritz sends executable to implant  
packet nbr 554: DanderSpritz sends executable to implant  
packet nbr 578: DanderSpritz sends executable to implant  
  Encrypted executable written to out.file.executable_encr  
  Original size of executable: 338944  
  Decrypted executable written to out.file.executable  

# TLS协议握手与协议组合的深度解构：从TLS 1.2到TLS 1.3的移动安全视角


&lt;!--more--&gt;

在移动应用安全领域，逆向工程师常面临一个核心挑战：如何快速理解私有通信协议的逻辑，尤其是那些试图模仿或改造TLS的自定义加密协议。这类协议往往通过混淆、非标字段或魔改算法来规避检测，但其底层设计仍可能暴露出与TLS相似的模式与漏洞。

**分析TLS协议的价值远不止于理解HTTPS流量：&amp;#x20;**

1. **协议设计范本**：TLS是经过严格验证的工业级协议，其握手流程、密钥交换机制和错误处理逻辑为自定义协议提供了“最佳实践”参考。逆向工程师可通过对比TLS标准，快速定位私有协议中的异常点（如缺失身份验证、弱随机数生成）。
2. ​**流量特征提取**：TLS握手阶段的明文特征（如`ClientHello`扩展类型、证书链顺序）可作为指纹，帮助识别私有协议中类似的握手阶段。
3. ​**密钥计算逆向**：TLS 1.3的精简设计（如密钥派生函数HKDF）展示了如何从少量参数生成密钥，此类模式常被自定义协议借鉴，分析其数学逻辑有助于破解私有协议的密钥生成过程。

本文将以**TLS 1.2与TLS 1.3的握手流程**为核心，解析其协议组合的底层逻辑，并提炼出一套逆向分析自定义协议的方法论，最终实现以下目标：

* 通过TLS协议逆向，构建通用协议分析框架；
* 识别私有协议中的典型设计缺陷（如降级攻击面、密钥复用）；
* 提供工具链与实战案例，加速私有协议的解密。

## 一、**TLS协议的核心目标与组件概述**

### 1.1 **SSL/TLS的演进历史**

其实早期的互联网协议基本都是不加密进行传输的，如**HTTP**、**FTP**等协议

**传输层安全性协议**（英语：**T**ransport **L**ayer **S**ecurity，缩写：**TLS**）及其前身**安全套接层**（英语：**S**ecure **S**ockets **L**ayer，缩写：**SSL**）的历史进程如下表所示：

| 协议      | 发布时间  | 状态        |
| ------- | ----- | --------- |
| SSL 1.0 | 未公布   | 未公布       |
| SSL 2.0 | 1995年 | 已于2011年弃用 |
| SSL 3.0 | 1996年 | 已于2015年弃用 |
| TLS 1.0 | 1999年 | 已于2020年弃用 |
| TLS 1.1 | 2006年 | 已于2020年弃用 |
| TLS 1.2 | 2008年 |           |
| TLS 1.3 | 2018年 |           |

* TLS 1.0 于1999年发布为[RFC 2246](https://www.rfc-editor.org/info/rfc2246)
* TLS 1.1 于2006年作为[RFC 4346](https://www.rfc-editor.org/info/rfc4346)发布
* TLS 1.2 于2008年发布为[RFC 5246](https://www.rfc-editor.org/info/rfc5246)
* TLS 1.3 于2018年8月作为建议标准在[RFC 8446](https://tools.ietf.org/html/rfc8446)发布

SSL（Secure Sockets Layer）是网景公司（Netscape）设计的主要用于Web的安全传输协议，这种协议在Web上获得了广泛的应用。SSL1.0没有被公开发布过，1995 网景公司发布SSL2.0，但是由于SSL2.0有严重的安全漏洞，因此1996年又发布了SSL3.0。

&gt; 但是在2014年10月，Google发布在SSL 3.0中发现设计缺陷，建议禁用此一协议。攻击者可以向TLS发送虚假错误提示，然后将安全连接强行降级到过时且不安全的SSL 3.0，然后就可以利用其中的设计漏洞窃取敏感信息。Google在自己公司相关产品中陆续禁止回溯兼容，强制使用TLS协议。Mozilla也在11月25日发布的Firefox 34中彻底禁用了SSL 3.0。微软同样发出了安全通告。**这就是SSL3.0在2015年被弃用的原因。**&amp;#x4F46;是由于SSL存在的时间太长了，人们以及习惯用SSL这个名词来指代加密的安全传输协议，因此我们要知道现在说的SSL绝大多数都是说的TLS加密。

众所周知当年的浏览器大战微软战胜了网景，而后网景将SSL协议的管理权交给了标准化组织IETF（Internet Engineering Task Force）。**1999年**，IETF在SSL3.0的基础上进行发布了TLS协议的1.0版本，需要注意的是TLS1.0版本和SSL3.0版本的区别很小，并且TLS1.0是可以降级到SSL3.0来使用的，之所以换名字主要是为了避免一些版权和法律的问题。这也就导致了后来谷歌禁止TLS回溯兼容SSL协议从而避免安全事故的发送。注意其实所有TLS版本在**2011年3月**发布的[RFC 6176](https://tools.ietf.org/html/rfc6176)中删除了对SSL2.0的兼容，这样TLS会话将永远无法协商使用的SSL 2.0以避免安全问题。**但是还是可以降级协商到SSL3.0的。**

TLS 1.1在 [RFC 4346](https://tools.ietf.org/html/rfc4346) 中定义，于2006年4月发表。TLS 1.2在 [RFC 5246](https://tools.ietf.org/html/rfc5246) 中定义，于2008年8月发表。TLS 1.3在 [RFC 8446](https://tools.ietf.org/html/rfc8446) 中定义，于2018年8月发表。实际上现代的浏览器已经基本不使用 SSL，使用的都是 TLS，而目前主流使用的加密协议版本是TLS1.2和TLS1.3。

### 1.2 **TLS的“分层”结构**

SSL/TLS最初是为了给HTTP协议加密使用，也就是HTTPS协议，通常来说我们可以认为`HTTP&#43;SSL/TLS=HTTPS`，而实际上现在我们的很多其他应用层协议都可以使用SSL/TLS，比如SSH、FTPS、POP3S、IMAPS等等。从五层网络模型上看，其工作的空间如下：

![](/posts/tls/tls-in-osi.png)

TLS协议是一个分层协议，其中握手协议（Handshake Protocol）和记录协议（Record Protocol）在安全通信中扮演不同但互补的角色

#### 1.2.1 ​**握手协议（Handshake Protocol）​**

1. **核心功能**：负责建立安全会话所需的参数，验证身份，并生成加密密钥。
2. **主要任务：**
   1. ​**协商参数**：客户端和服务器交换支持的TLS版本、加密套件（如AES-GCM、RSA等）和压缩方法（现代TLS通常禁用）。
   2. ​**身份验证**：服务器通过数字证书验证身份（客户端验证可选）。
   3. ​**密钥交换**：通过Diffie-Hellman等算法生成共享密钥材料，避免明文传输密钥。
   4. ​**生成会话密钥**：基于预主密钥和随机数，派发生成对称加密密钥（如会话密钥）和初始化向量（IV）。
   5. ​**完成握手**：双方确认协商参数一致，准备切换至加密通信。
3. **适用场景**
   1. 仅在连接初始化或会话恢复时运行（如TLS 1.3的0-RTT或1-RTT握手）。
   2. 在TLS 1.3中，部分握手消息可能被记录协议加密传输。

#### 1.2.2 **记录协议（Record Protocol）​**

1. **功能核心：**&amp;#x8D1F;责所有数据的加密、完整性保护和传输，无论数据来源是握手消息还是应用层。
2. **主要任务**
   1. ​**分块处理**：将上层数据（如HTTP请求）分割为不超过16KB的块。
   2. ​**加密与完整性保护**：使用握手协议生成的密钥，对数据应用对称加密（如AES）和MAC（如HMAC，TLS 1.3使用AEAD）。
   3. ​**封装传输**：添加记录头（类型、版本、长度），形成TLS记录传输。
   4. ​**处理多种数据类型**：包括握手协议、警报协议、应用数据等。
3. ​**适用场景**
   * 在握手阶段：可能加密部分握手消息（如TLS 1.3的加密扩展）。
   * 在应用阶段：加密传输HTTP等应用数据。

通过对两层协议的大致了解，可以看出

* **握手协议**是“谈判专家”，确保双方安全参数一致并生成密钥。
* ​**记录协议**是“执行者”，确保所有传输数据的安全性和完整性。
* ​**协同工作**：握手协议建立安全基础，记录协议基于此基础保护实际通信，两者共同构建端到端的安全通道。

## 二、**TLS 1.2握手流程的逐层拆解**

下面将结合RFC文档、CS源码、Wireshark抓包这三个角度来讲解，资源来自于
- [The Illustrated TLS 1.2 Connection: Every byte explained](https://tls12.ulfheim.net/)
- [The Illustrated TLS 1.2 Connection - Github](https://github.com/syncsynchalt/illustrated-tls)

### 2.1 **完整握手流程**

首先通过官方RFC文档初步认识下一个完整的握手流程
```
 Client                                               Server

      ClientHello                  --------&gt;
                                                      ServerHello
                                                     Certificate*
                                               ServerKeyExchange*
                                              CertificateRequest*
                                   &lt;--------      ServerHelloDone
      Certificate*
      ClientKeyExchange
      CertificateVerify*
      [ChangeCipherSpec]
      Finished                     --------&gt;
                                               [ChangeCipherSpec]
                                   &lt;--------             Finished
      Application Data             &lt;-------&gt;     Application Data

             Figure 1.  Message flow for a full handshake
```

&gt; *号表示可选步骤或与实际握手情况相关。比如重建已有连接，服务端无需执行Certificate，再比如使用RSA公钥加密时，无需ServerKeyExchange。

搭配Wireshark看看实际抓包中握手的流程

![](/posts/tls/wireshark_handshake.png)

从上图中可以得到一些初步理解：
- 整个握手过程经历了四次数据传输
- 每次传输中都带有至少一个数据包

完整的握手流程有时候也被称为`2-RTT`流程，即完整的握手流程需要客户端和服务端交互2次才能完成握手。

仔细看抓包中红框数据包的地方可以发现，每个数据所在的层级都是`Record Layer`，每个数据包细分又可以得到`Handshake Protocol`，这也印证了上文提到的TLS“分层”架构，底层`Record Layer`负责装载上层传来的数据包

Record层有其对应的结构，在接收到上层传来的数据包时完成封装
```c
struct {
    uint8 major;
    uint8 minor;
} ProtocolVersion;

enum {
    change_cipher_spec(20), alert(21), handshake(22),
    application_data(23), (255)
} ContentType;

struct {
    ContentType type;
    ProtocolVersion version;
    uint16 length;
    opaque fragment[TLSPlaintext.length];
} TLSPlaintext;
```
从上述定义可以看到Record的前两字节是用于定义协议版本，但是从上图我们发现`TLS 1.2`对应的版本为`0303`，这乍看起来有点别扭，但其实是历史发展的结果。历史上TLS由SSL进化而来，通常也统称为`SSL/TLS`，因此版本对应关系分别是:

- SSL 3.0 -&gt; 0300
- TLS 1.0 -&gt; 0301
- TLS 1.1 -&gt; 0302
- TLS 1.2 -&gt; 0303
- TLS 1.3 -&gt; 0304
- …

这个版本号字段虽然不是很重要，但是却可以作为TLS协议的特征记录下来

#### 2.1.1 **STEP 1**
##### 2.1.1.1 **Client Hello**

当客户端首次与服务端建立连接或需要重新协商加密握手会话时，需要将`Client Hello`作为第一条消息发送给服务端，就像TCP连接需要发送`SYN` 一样，告诉服务端你要建立一个TLS连接，关于`ClientHello`的结构如下

```c
struct {
       ProtocolVersion client_version;
       Random random;
       SessionID session_id;
       CipherSuite cipher_suites&lt;2..2^16-2&gt;;
       CompressionMethod compression_methods&lt;1..2^8-1&gt;;
       select (extensions_present) {
           case false:
               struct {};
           case true:
               Extension extensions&lt;0..2^16-1&gt;;
       };
   } ClientHello;
```

* `client_version`：指客户端版本，值为 `0x0303`，表示TLS 1.2。值得一提的是该值与Record中的版本不一定一致，后者由于兼容性的原因通常会设置为一个较旧的版本(比如 TLS 1.0)，服务端应当以 ClientHello中指定的版本为准，作用是告诉服务端当前客户端所支持的最新版本，以便后续服务端根据对应版本进行后续协商流程。
* `random`：是客户端本地生成的**32 字节**随机数，在[RFC5246](https://datatracker.ietf.org/doc/html/rfc5246)中提到随机数的前四字节应该是客户端的本地时间戳，但后来发现这样会存在[针对客户端或者服务端的设备指纹标记](https://tools.ietf.org/html/draft-mathewson-no-gmtunixtime-00)，因此已经不建议使用时间戳了。`random`的作用是为了增强加密密钥的安全性，作为随机因子，通过该随机数使用基于HMAC的PRF算法生成客户端和服务端的密钥。
 
  `random`的值来源于`illustrated-tls12/captures/keylog.txt`文件，固定为：
  ```
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  ```
* `session_id`：主要用于恢复加密链接，需要客户端和服务端同时支持。由于秘钥协商的过程中涉及到很多费时的操作，对于短链接而言将之前协商好的加密通道恢复可以大大减少运算资源。如果服务器支持恢复会话，那么后续可以直接进入加密通信，否则还是需要进行完整的握手协商。该字段的长度是可变的，占1字节，也就是说数据部分最多可以长达255字节。
* `cipher_suites`：表示客户端所支持的加密套件，带有2字节长度字段，每个加密套件用2字节表示，且优先级高的排在前面。作用是和服务端协商加密算法，服务端根据支持算法在ServerHello返回一个最合适的算法组合。算法套件的格式为TLS\_密钥交换算法\_身份认证算法\_WITH\_对称加密算法\_消息摘要算法，比如`TLS_DHE_RSA_WITH_AES_256_CBC_SHA256`，密钥交换算法是`DHE`，身份认证算法是`RSA`，对称加密算法是AES\_256\_CBC，消息摘要算法是SHA256，由于RSA又可以用于加密也可以用于身份认证，因此密钥交换算法使用RSA时，只写一个RSA，比如`TLS_RSA_WITH_AES_256_CBC_SHA256`。
  
  在本地可以通过使用`openssl`可以查看实现的加密套件列表，如下所示:  
  ```shell
  $ openssl ciphers -V | column -t
  0x13,0x02  -  TLS_AES_256_GCM_SHA384         TLSv1.3  Kx=any       Au=any    Enc=AESGCM(256)             Mac=AEAD
  0x13,0x03  -  TLS_CHACHA20_POLY1305_SHA256   TLSv1.3  Kx=any       Au=any    Enc=CHACHA20/POLY1305(256)  Mac=AEAD
  0x13,0x01  -  TLS_AES_128_GCM_SHA256         TLSv1.3  Kx=any       Au=any    Enc=AESGCM(128)             Mac=AEAD
  0xC0,0x2C  -  ECDHE-ECDSA-AES256-GCM-SHA384  TLSv1.2  Kx=ECDH      Au=ECDSA  Enc=AESGCM(256)             Mac=AEAD
  0xC0,0x30  -  ECDHE-RSA-AES256-GCM-SHA384    TLSv1.2  Kx=ECDH      Au=RSA    Enc=AESGCM(256)             Mac=AEAD
  0x00,0x9F  -  DHE-RSA-AES256-GCM-SHA384      TLSv1.2  Kx=DH        Au=RSA    Enc=AESGCM(256)             Mac=AEAD
  0xCC,0xA9  -  ECDHE-ECDSA-CHACHA20-POLY1305  TLSv1.2  Kx=ECDH      Au=ECDSA  Enc=CHACHA20/POLY1305(256)  Mac=AEAD
  ```
  每个加密套件包含一个秘钥交换算法、一个认证算法、一个对称加密算法和一个用于完整性校验的MAC算法。例如后文中协商出的加密套件`0x13,0x02`表示`TLS_AES_256_GCM_SHA384`。
* `compression_methods`：表示客户端所支持的一系列压缩算法。数据需要先压缩后加密，因为加密后的数据通常很难压缩。但是压缩的数据在加密中会受到类似[CRIME](https://en.wikipedia.org/wiki/CRIME)攻击的影响，因此在TLS1.3中已经将TLS压缩功能去除，TLS1.2算法也建议不启用压缩功能。
* `extensions`：可以在不改变底层协议的情况下，添加附加功能。客户端使用扩展请求其他功能，服务端若不提供这些功能，客户端可能会中止握手。对于扩展字段的详细定义可以看[Transport Layer Security (TLS) Extensions](https://tools.ietf.org/html/rfc4366)

![](/posts/tls/ClientHello.png)

客户端发送完 `ClientHello` 消息后，将等待 `ServerHello` 消息。 服务端返回的任何握手消息（`HelloRequest` 除外）都将被视为异常

#### 2.1.2 **STEP 2**

##### 2.1.2.1 **Server Hello**

当服务端接收到`ClientHello`，则开始TLS握手流程， 服务端需要根据客户端提供的加密套件，协商一个合适的算法簇，其中包括对称加密算法、身份验证算法、非对称加密算法以及消息摘要算法。若服务端不能找到一个合适的算法簇匹配项，则会响应握手失败的预警消息。关于`ServerHello`的结构如下

```c
struct {
       ProtocolVersion server_version;
       Random random;
       SessionID session_id;
       CipherSuite cipher_suite;
       CompressionMethod compression_method;
       select (extensions_present) {
           case false:
               struct {};
           case true:
               Extension extensions&lt;0..2^16-1&gt;;
       };
   } ServerHello;
```

* `client_version`：服务端根据客户端发送的版本号返回一个服务端支持的最高版本号。若客户端不支持服务端选择的版本号，则客户端必须发送`protocol_version`的alert消息并关闭连接。
* `random`：逻辑和客户端相同，在案例中服务端返回的随机数是
  ```
  707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f
  ```
* `session_id`：若客户端提供了会话ID，则可以校验是否与历史会话匹配
  * 若不匹配，则服务端可以选择直接使用客户端的会话ID或根据自定义规则生成一个新的会话ID，客户端需要保存服务端返回的会话ID当作本次会话的ID
  * 若匹配，则可以直接执行1-RTT握手流程，返回ServerHello后直接返回`ChangeCipherSpec`和`Finished`消息。
  ```
  Client                                                Server

        ClientHello                   --------&gt;
                                                         ServerHello
                                                  [ChangeCipherSpec]
                                      &lt;--------             Finished
        [ChangeCipherSpec]
        Finished                      --------&gt;
        Application Data              &lt;-------&gt;     Application Data

            Figure 2.  Message flow for an abbreviated handshake
  ```
  
* `cipher_suites`：服务端根据客户端提供的算法套件列表和自己当前支持算法进行匹配，选择一个最合适的算法组合，若没有匹配项，则使用默认的`TLS_RSA_WITH_AES_128_CBC_SHA`。案例中使用到`0xc013`也就是`Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)`
  &gt; TLS1.2协议要求客户端和服务端都必须实现密码套件`TLS_RSA_WITH_AES_128_CBC_SHA`
* `compression_methods`：逻辑和客户端相同
* `extensions`：服务端需要支持接收具有扩展和没有扩展的ClientHello。服务端响应的扩展类型必须是`ClientHello`出现过才行，否则客户端必须响应`unsupported_extension`严重警告并中断握手。

![](/posts/tls/ServerHello.png)

通过`ClientHello`和`ServerHello`，客户端和服务端就协商好算法套件和用于生成密钥的随机数。

##### 2.1.2.2 **Server Certificate**

假设客户端和服务端使用默认的`TLS_RSA_WITH_AES_128_CBC_SHA`算法，在`ServerHello`完成后，服务端必须将本地的RSA证书传给客户端，以便客户端和服务端之间可以进行非对称加密保证对称加密密钥的安全性。

RSA的证书有2个作用：

* 客户端可以对服务端的证书进行合法性进行校验。
* 对`Client Key Exchange`生成的pre-master key进行公钥加密，保证只有服务端可以解密，确保对称加密密钥的安全性。

通常服务器会返回多个证书，因为当前域名往往不是由根证书直接签名的，而是使用由于根证书所签名的次级证书去签发具体域名的证书。

如果使用了多级证书，那么返回的证书列表中第一个必须是对应域名的证书，而后每个证书都是前一个证书的 issuer，且最后一个证书是由系统中某个根证书签发的，注意根证书本身并不会一起返回。以`baidu.com`为例，实际返回的证书列表如下:
```shell
$ openssl s_client -connect baidu.com:443
CONNECTED(00000006)
depth=2 C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root G2
verify return:1
depth=1 C = US, O = &#34;DigiCert, Inc.&#34;, CN = DigiCert Secure Site Pro G2 TLS CN RSA4096 SHA256 2022 CA1
verify return:1
depth=0 C = CN, ST = \E5\8C\97\E4\BA\AC\E5\B8\82, O = &#34;BeiJing Baidu Netcom Science Technology Co., Ltd&#34;, CN = www.baidu.cn
verify return:1
---
Certificate chain
 0 s:C = CN, ST = \E5\8C\97\E4\BA\AC\E5\B8\82, O = &#34;BeiJing Baidu Netcom Science Technology Co., Ltd&#34;, CN = www.baidu.cn
   i:C = US, O = &#34;DigiCert, Inc.&#34;, CN = DigiCert Secure Site Pro G2 TLS CN RSA4096 SHA256 2022 CA1
 1 s:C = US, O = &#34;DigiCert, Inc.&#34;, CN = DigiCert Secure Site Pro G2 TLS CN RSA4096 SHA256 2022 CA1
   i:C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root G2
 2 s:C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root G2
   i:C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root CA
```
实际返回了三个证书，最后一个证书由`DigiCert Global Root CA`签发。

如果服务端需要校验客户端证书的话，随后会发送一个`Certificate Request`请求，然后客户端返回对应的`Client Certificate`进行一轮额外的信息交换，当然这一步是可选的，从RFC的握手流程中也可以看出是这一步是可选的。

![](/posts/tls/ServerCertificate.png)

##### 2.1.2.3 **Server Key Exchange**

使用RSA公钥加密，必须要保证服务端私钥的安全。若私钥泄漏，则使用公钥加密的对称密钥就不再安全。同时RSA是基于大数因式分解。密钥位数必须足够大才能避免密钥被暴力破解。

&gt; 1999年，RSA-155 (512 bits) 被成功分解。
&gt; 2009年12月12日，RSA-768 (768 bits)也被成功分解。
&gt; 在2013年的棱镜门事件中，某个CA机构迫于美国政府压力向其提交了CA的私钥，这就是十分危险的。

相比之下，使用DH算法通过双方在不共享密钥的情况下双方就可以协商出共享密钥，避免了密钥的直接传输。DH算法是基于离散对数，计算相对较慢。而基于椭圆曲线密码（ECC）的DH算法计算速度更快，而且用更小的Key就能达到RSA加密的安全级别。ECC密钥长度为224\~225位几乎和RSA2048位具有相同的强度。

&gt; ECDH：基于ECC的DH算法。

简单来说，ECDH可以在通信媒介不可信的情况下安全地完成秘钥交换。算法流程文字描述如下：

- 客户端随机生成随机值`Ra`，计算`Pa(x, y) = Ra * Q(x, y)`，`Q(x, y)`为全世界公认的某个椭圆曲线算法的基点。将`Pa(x, y)`发送至服务器。

- 服务器随机生成随机值`Rb`，计算`Pb(x,y) = Rb * Q(x, y)`。将`Pb(x, y)`发送至客户端。

- 客户端计算`Sa(x, y) = Ra * Pb(x, y)`；服务器计算`Sb(x, y) = Rb *Pa(x, y)`。

- 算法保证了`Sa = Sb = S`，提取其中的`S`的`x`向量作为密钥（预主密钥）。

双方只需要知道对方的公钥，可以在不暴露私钥的情况下实现信息的交换，防止中间人攻击，所交换的信息就是后续使用的对称加密秘钥。

但是需要注意这里有一个问题，那就是依据ECDH的实现来看，服务端的私钥是固定的，也就是证书的私钥，同样存在泄露风险，而一旦私钥被泄露，那么其他会话数据都能正常解开。

更进一步，为了避免未来私钥泄露导致以前的通信被解密，通常交换时并不直接使用原始公私钥，而是一个随机生成的新公私钥对，只需要用原始私钥进行认证。这种交换方式也称为ECDHE，其中 `E` 表示 `Ephemeral`，而这种做法所带来的称为`Forward Security`，即[前向安全](https://zh.wikipedia.org/wiki/%E5%89%8D%E5%90%91%E4%BF%9D%E5%AF%86)。

回到案例中，服务端选择的椭圆曲线为`x25519`，首先生成一个临时私钥，长度为32字节，从[illustrated-tls12的动画演示](https://tls12.xargs.org/#server-key-exchange-generation)上可以确认生成的私钥为：
```
909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf
```
对应的公钥是
```
9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615
```
通过openssl验证正确性
```shell
$ openssl pkey -noout -text &lt; server-ephemeral-private.key

X25519 Private-Key:
priv:
    90:91:92:93:94:95:96:97:98:99:9a:9b:9c:9d:9e:
    9f:a0:a1:a2:a3:a4:a5:a6:a7:a8:a9:aa:ab:ac:ad:
    ae:af
pub:
    9f:d7:ad:6d:cf:f4:29:8d:d3:f9:6d:5b:1b:2a:f9:
    10:a0:53:5b:14:88:d7:f8:fa:bb:34:9a:98:28:80:
    b6:15
```

`ServerKeyExchange`的消息格式如下：

```c
struct {
          select (KeyExchangeAlgorithm) {
              case dh_anon:
                  ServerDHParams params;
              case dhe_dss:
              case dhe_rsa:
                  ServerDHParams params;
                  digitally-signed struct {
                      opaque client_random[32];
                      opaque server_random[32];
                      ServerDHParams params;
                  } signed_params;
              case rsa:
              case dh_dss:
              case dh_rsa:
                  struct {} ;
                 /* message is omitted for rsa, dh_dss, and dh_rsa */
              /* may be extended, e.g., for ECDH -- see [TLSECC] */
          };
      } ServerKeyExchange;
```
不同的加密套件有不同的格式，由于我们的是`dhe_rsa`，因此在消息中应当包含椭圆曲线参数，以及`ClientRandom&#43;ServerRandom&#43;参数`的签名信息。使用原始私钥来计算最终的签名信息:
```shell
### client random from Client Hello
$ echo -en &#39;\x00\x01\x02\x03\x04\x05\x06\x07&#39;  &gt; /tmp/compute
$ echo -en &#39;\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f&#39; &gt;&gt; /tmp/compute
$ echo -en &#39;\x10\x11\x12\x13\x14\x15\x16\x17&#39; &gt;&gt; /tmp/compute
$ echo -en &#39;\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f&#39; &gt;&gt; /tmp/compute
### server random from Server Hello
$ echo -en &#39;\x70\x71\x72\x73\x74\x75\x76\x77&#39; &gt;&gt; /tmp/compute
$ echo -en &#39;\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f&#39; &gt;&gt; /tmp/compute
$ echo -en &#39;\x80\x81\x82\x83\x84\x85\x86\x87&#39; &gt;&gt; /tmp/compute
$ echo -en &#39;\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f&#39; &gt;&gt; /tmp/compute
### the curve info section from this message
$ echo -en &#39;\x03\x00\x1d&#39; &gt;&gt; /tmp/compute
### the public key sections from this msg
$ echo -en &#39;\x20\x9f\xd7\xad\x6d\xcf\xf4\x29&#39; &gt;&gt; /tmp/compute
$ echo -en &#39;\x8d\xd3\xf9\x6d\x5b\x1b\x2a\xf9&#39; &gt;&gt; /tmp/compute
$ echo -en &#39;\x10\xa0\x53\x5b\x14\x88\xd7\xf8&#39; &gt;&gt; /tmp/compute
$ echo -en &#39;\xfa\xbb\x34\x9a\x98\x28\x80\xb6\x15&#39; &gt;&gt; /tmp/compute
$ openssl dgst -sign server.key -sha256 /tmp/compute | hexdump

0000000 04 02 b6 61 f7 c1 91 ee 59 be 45 37 66 39 bd c3
... snip ...
00000f0 7d 87 dc 33 18 64 35 71 22 6c 4d d2 c2 ac 41 fb
```

注意这里之所以这么操作是因为服务端和客户端已经同意使用临时密钥进行密钥交换，所以它们没有使用与服务端证书关联的公钥和私钥。为了证明服务端拥有证书（引出下一步服务端证书验证），它使用与服务端证书关联的私钥对临时公钥进行签名。可以使用服务端证书中包含的公钥验证此签名，而服务端的证书在`Server Certificate`中已经下发

![](/posts/tls/ServerKeyExchange.png)

##### 2.1.2.4 **Server Hello Done**

当服务端处理Hello请求结束时，发送`Server Hello Done`消息，然后等待接收客户端握手消息。客户端收到服务端该消息，有必要时需要对服务端的证书进行有效性校验。`ServerHelloDone`无需数据。

```c
struct { } ServerHelloDone;
```

#### 2.1.3 **STEP 3**

##### 2.1.3.1 **Client Key Exchange**

客户端收到ClientKeyExchange后，得知服务器的方式生成临时密钥，同理也相应的生成临时密钥
```
202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
```
并生成公钥
```
358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254
```

ClientKeyExchange格式如下：

```c
struct {
          select (KeyExchangeAlgorithm) {
              case rsa:
                  EncryptedPreMasterSecret;
              case dhe_dss:
              case dhe_rsa:
              case dh_dss:
              case dh_rsa:
              case dh_anon:
                  ClientDiffieHellmanPublic;
          } exchange_keys;
      } ClientKeyExchange;
```

其格式相对简单，对于我们选择的加密套件而言只需要包含临时生成的ECDH公钥。注意此处与Server Key Exchange不同，并没有对客户端的公钥进行签名（当然，客户端要进行签名的话需要证书，也存在泄露风险），也就是说可以被中间人进行替换。不过协议设计的时候已经考虑到了这一点，因为此时双方已经有足够的信息去协商秘钥并且进行验证了，通过后文的计算过程也可以确认这一点。

![](/posts/tls/ClientKeyExchange.png)

##### 2.1.3.2 **Client Change Cipher Spec**

该数据包告诉服务器客户端已经计算好了共享秘钥，并且后续客户端发送给服务器的数据都将使用共享秘钥进行加密。在**TLS1.3**中该数据包类型将会被移除，因为加密数据是可以通过数据类型推断的。

那么，客户端是如何计算出共享秘钥的呢？目前客户端所已知的数据为:

* client\_random
* server\_random
* server-ephemeral-public.key
* client-ephemeral-private.key

首先根据前文对ECDH的介绍，通过对方的公钥和自己的私钥，可以计算出一个共同秘钥，这里称之为`PMS(Pre-Master-Secret)`。具体计算方法可以参考[curve25519-mult.c](https://tls12.ulfheim.net/files/curve25519-mult.c):
```shell
$ gcc -o curve25519-mult curve25519-mult.c
$ ./curve25519-mult client-ephemeral-private.key \
                    server-ephemeral-public.key | hexdump

0000000 df 4a 29 1b aa 1e b7 cf a6 93 4b 29 b4 74 ba ad
0000010 26 97 e2 9f 1f 92 0d cc 77 c8 a0 a0 88 44 76 24
```
实际上服务端计算出的共享秘钥也是一样的:
```shell
$ ./curve25519-mult server-ephemeral-private.key \
                    client-ephemeral-public.key | hexdump

0000000 df 4a 29 1b aa 1e b7 cf a6 93 4b 29 b4 74 ba ad
0000010 26 97 e2 9f 1f 92 0d cc 77 c8 a0 a0 88 44 76 24
```

该共享秘钥计算过程只涉及自身私钥和对方的公钥，为了进一步将共享秘钥关联当当前会话中，需要为其加入双方的随机数，当然不能直接相加，需要增加随机性，因此使用到了一个伪随机函数，称为`PRF(pseudorandom function)`。其计算方式如下：

```c
seed = &#34;master secret&#34; &#43; client_random &#43; server_random
a0 = seed
a1 = HMAC-SHA256(key=PreMasterSecret, data=a0)
a2 = HMAC-SHA256(key=PreMasterSecret, data=a1)
p1 = HMAC-SHA256(key=PreMasterSecret, data=a1 &#43; seed)
p2 = HMAC-SHA256(key=PreMasterSecret, data=a2 &#43; seed)
MasterSecret = p1[all 32 bytes] &#43; p2[first 16 bytes]
```

所得到的的 48 字节拓展秘钥称为`主密钥(Master Secret)`，其值为
```
916abf9da55973e13614ae0a3f5d3f37b023ba129aee02cc9134338127cd7049781c8e19fc1eb2a7387ac06ae237344c
```

在使用时需要将该主密钥进行拓展(至任意长度)，并将结果的不同部分分别用作不同秘钥：

```c
seed = &#34;key expansion&#34; &#43; server_random &#43; client_random
a0 = seed
a1 = HMAC-SHA256(key=MasterSecret, data=a0)
a2 = HMAC-SHA256(key=MasterSecret, data=a1)
a3 = HMAC-SHA256(key=MasterSecret, data=a2)
a4 = ...
p1 = HMAC-SHA256(key=MasterSecret, data=a1 &#43; seed)
p2 = HMAC-SHA256(key=MasterSecret, data=a2 &#43; seed)
p3 = HMAC-SHA256(key=MasterSecret, data=a3 &#43; seed)
p4 = ...
p = p1 &#43; p2 &#43; p3 &#43; p4 ...
client write mac key = [first 20 bytes of p]
server write mac key = [next 20 bytes of p]
client write key = [next 16 bytes of p]
server write key = [next 16 bytes of p]
client write IV = [next 16 bytes of p]
server write IV = [next 16 bytes of p]
```

最终秘钥分成了6个部分，分别是客户端和服务端的MAC秘钥、数据加密秘钥和初始向量。这里涉及到几个有趣的问题，比如：

* 为什么客户端和服务端要使用不同的数据加密秘钥？
* 为什么客户端和服务端要使用不同的MAC秘钥？
* 为什么要单独指定IV？

根据`RFC5246`中的介绍，使用不同的MAC秘钥是为了防止来自一方的数据被注入到另一方中；对于使用流密钥加密的情况，客户端和服务端使用不同的秘钥也能防止秘钥重用攻击。

在TLS1.0中的CBC使用了前一部分Record的数据作为IV导致了选择明文攻击(chosenplaintextattack)，因此这在新版本中的TLS协议明确指定了IV的生成方法。注意这个IV只有部分需要额外指定IV的AEAD算法会用到。

总而言之，通过`ECDHE秘钥交换`，客户端计算出了下述秘钥:
```shell
client MAC key: 1b7d117c7d5f690bc263cae8ef60af0f1878acc2
server MAC key: 2ad8bdd8c601a617126f63540eb20906f781fad2
client write key: f656d037b173ef3e11169f27231a84b6
server write key: 752a18e7a9fcb7cbcdd8f98dd8f769eb
client write IV: a0d2550c9238eebfef5c32251abb67d6
server write IV: 434528db4937d540d393135e06a11bb8
```

##### 2.1.3.3 **Client Handshake Finished**

该数据包告诉服务器，客户端的握手流程也已经完成。同时，还携带了一部分加密数据，所加密的内容称为 **Verify Data**，用以验证握手成功且没有被中间人修改过。

**Verify Data**的内容是该消息之前的所有握手包的HASH经过HMAC计算出来的一个 12 字节数据，其计算方法为：

```
seed = &#34;client finished&#34; &#43; SHA256(all handshake messages)
a0 = seed
a1 = HMAC-SHA256(key=MasterSecret, data=a0)
p1 = HMAC-SHA256(key=MasterSecret, data=a1 &#43; seed)
verify_data = p1[first 12 bytes]
```

在示例数据包中，`verify_data`值为`cf919626f1360c536aaad73a`，使用`client_write_key`进行加密，服务端收到后使用对应的秘钥进行解密，所使用加解密算法由之前协商的加密套件决定，这里是`aes-128-cbc`。

#### 2.1.4 **STEP 4**

##### 2.1.4.1 **Server Change Cipher Spec**

服务端收到上述加密后的数据为(Record Body):
```
404142434445464748494a4b4c4d4e4f
227bc9ba81ef30f2a8a78ff1df50844d
5804b7eeb2e214c32b6892aca3db7b78
077fdd90067c516bacb3ba90dedf720f
```

为了进行验证，服务端使用相同的方式计算出共享秘钥`Pre Master Secret`，由ECDH的特性可以得知服务端和客户端计算出的`PMS`是相同的，因衍生出来的对称加密秘钥、IV、MAC秘钥也是相同的。

因此服务端收到加密数据后，可以使用协商出来的client\_write\_key对其进行解密
```shell
hexdata=227bc9ba81ef30f2a8a78ff1df50844d5804b7eeb2e214c32b6892aca3db7b78077fdd90067c516bacb3ba90dedf720f
# client write key
hexkey=f656d037b173ef3e11169f27231a84b6
# record iv，保存在加密数据之前
hexiv=404142434445464748494a4b4c4d4e4f

$ echo -n $hexdata | xxd -r -p | openssl enc -d -nopad -aes-128-cbc -K $hexkey -iv $hexiv | rax2 -S
1400000ccf919626f1360c536aaad73a
a5a03d233056e4ac6eba7fd9e5317fac
2db5b70e0b0b0b0b0b0b0b0b0b0b0b0b
```

&gt;需要注意的是这里使用的key是协商的client_write_key，但IV并不是client_write_iv，而是一个随机生成的针对当前Record的IV，并且附加到加密数据的前方。

在解密后的数据中，`1400000c`是Record的子协议头部，对应`Handshake/Finish`，长度0x0c即12字节，数据正好是前面计算出的`verify_data`的值，即`cf919626f1360c536aaad73a`。

末尾还有32字节的数据，是使用client_mac_key计算的签名，用于确保所接收数据的完整性，计算方法为:
```shell
### from https://tools.ietf.org/html/rfc2246#section-6.2.3.1
$ sequence=&#39;0000000000000000&#39;
$ rechdr=&#39;16 03 03&#39;
$ datalen=&#39;00 10&#39;
$ data=&#39;14 00 00 0c cf 91 96 26 f1 36 0c 53 6a aa d7 3a&#39;
### client MAC key
$ mackey=1b7d117c7d5f690bc263cae8ef60af0f1878acc2
$ echo $sequence $rechdr $datalen $data | xxd -r -p \
  | openssl dgst -sha1 -mac HMAC -macopt hexkey:$mackey

a5a03d233056e4ac6eba7fd9e5317fac2db5b70e
```

这样服务端通过

* 将客户端发送的verify\_data与自身计算的值进行比对，可确保整个握手流程的完整性；
* 使用HMAC校验当前数据可以保证消息没有被中间人篡改。

在这些校验都完成后，服务端给客户端返回`Change Cipher Spec`消息，告知客户端接下来发送的数据都将经过协商秘钥进行加密。

##### 2.1.4.2 **Server Handshake Finished**

此时，服务端已经完成了握手的所有流程，并且也确认这个握手流程没有被中间人篡改，但是还需要通知客户端，因此类似于Client Handshake Finished，服务端也要发送一个加密并验签的数据给客户端，让客户端进行验证并确认整个握手流程的正确性。

发送的数据格式和Client Finished几乎一样，除了使用的key更换成`server_write_key`，并且`verify_data` 与前者相比还多了一个`Client Finished`消息，毕竟协议中说的是用于验证 “当前消息前的所有握手消息”。

客户端收到Server Finished后，同样进行解密并校验HMAC，如果确认无误就可以开始发送应用数据了。

#### 2.1.5 **Application Data**

Application Data是一个单独类型的Record(type=23)，准确来说已经不属于握手阶段了，不过这里还是提一下。

该消息格式中主要是使用协商秘钥加密的应用数据，客户端发送的数据使用client write key进行加密，服务端返回的数据使用server write key进行加密，并且`明文`数据末尾还加了HMAC校验数据，使用对应的MAC key进行签名，加解密和签名过程和Client/Server Finished消息的过程一致。因此每条应用数据都可以保证机密性和完整性。

回顾之前的所有流程，再对比下图来巩固下

![](/posts/tls/TLSv1.2-handshake.png)


### 2.2 **会话恢复机制**

TODO： Session ID与Session Ticket的区别与风险

## 三、**TLS 1.3的协议重组与握手简化**

### 3.1 **协议消息的“合并”与“弃用”​**

由于TLS 1.3是在TLS 1.2的基础上优化而来的，因此对于与上节实现相同的部分就不再详细介绍了，而只关注其中不同的部分。

总体来看，TLS 1.3与TLS 1.2相比，较大的差异有下面这些:

* 去除了一大堆过时的对称加密算法，只留下较为安全的AEAD(Authenticated Encryption with Associated Data)算法；加密套件(cipher suite)的概念被修改为单独的认证、秘钥交换算法以及秘钥拓展和MAC用到的哈希算法；
* 去除了静态RSA和秘钥交换算法套件，使目前所有基于公钥的交换算法都能保证前向安全；
* 引入了0-RTT(round-trip time) 的模式，减少握手的消息往返次数；
* `ServerHello`之后所有的握手消息都进行了加密；
* 修改了秘钥拓展算法，称为HKDF(HMAC-based Extract-and-Expand Key Derivation Function)；
* 废弃了TLS 1.2中的协议版本协商方法，改为使用Extension实现；
* TLS 1.2中的会话恢复功能现在采用了新的 PSK 交换实现；
* ……

下面将结合RFC文档、CS源码、Wireshark抓包这三个角度来讲解，资源来自于

* [The Illustrated TLS 1.3 Connection: Every byte explained](https://tls13.ulfheim.net/)
* [The Illustrated TLS 1.3 Connection - Github](https://github.com/syncsynchalt/illustrated-tls13)

照惯例通过官方RFC文档初步认识下一个完整的握手流程

```
       Client                                           Server

Key  ^ ClientHello
Exch | &#43; key_share*
     | &#43; signature_algorithms*
     | &#43; psk_key_exchange_modes*
     v &#43; pre_shared_key*       --------&gt;
                                                  ServerHello  ^ Key
                                                 &#43; key_share*  | Exch
                                            &#43; pre_shared_key*  v
                                        {EncryptedExtensions}  ^  Server
                                        {CertificateRequest*}  v  Params
                                               {Certificate*}  ^
                                         {CertificateVerify*}  | Auth
                                                   {Finished}  v
                               &lt;--------  [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}              --------&gt;
       [Application Data]      &lt;-------&gt;  [Application Data]

              &#43;  Indicates noteworthy extensions sent in the
                 previously noted message.

              *  Indicates optional or situation-dependent
                 messages/extensions that are not always sent.

              {} Indicates messages protected using keys
                 derived from a [sender]_handshake_traffic_secret.

              [] Indicates messages protected using keys
                 derived from [sender]_application_traffic_secret_N.

               Figure 1: Message Flow for Full TLS Handshake
```

如果大家对于TLS1.2还有印象的话就会发现有几个变化

1. 整个握手流程减少了一次服务端的回调
2. 新增了key\_share、pre\_shared\_key等等新的结构

![](/posts/tls/wireshark_handshake_1.3.png)


整个流程目前只有`1RTT`，相比较之前的减少了一倍，在通信效率方面的提升巨大，而且还存在`0RTT`的模式，下面就通过具体的握手流程来分析下TLS1.3带来的变化

#### 3.1.1 **STEP 1**

##### 3.1.1.1 **Client Hello**

与TLS1.2一样，握手总是以Client发送Hello请求开始。但正如本节开头所说，TLS握手时的协议协商不再使用Handshake/Hello中的version字段，虽然是1.3版本，但请求中version还是指定1.2版本，这是因为有许多web中间件在设计时候会忽略不认识的TLS版本号，因此为了兼容性，版本号依旧保持不变。实际协商TLS版本是使用的是SupportedVersions拓展实现的。`ClientHello`的结构如下

```c
struct {
          ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
          Random random;
          opaque legacy_session_id&lt;0..32&gt;;
          CipherSuite cipher_suites&lt;2..2^16-2&gt;;
          opaque legacy_compression_methods&lt;1..2^8-1&gt;;
          Extension extensions&lt;8..2^16-1&gt;;
      } ClientHello;
```

`random`是客户端生成的随机数，这里是:
```
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

`session_id`字段在此前的版本中该字段被用于恢复TLS会话，不过在TLS1.3中会话恢复使用了一种更为灵活的PSK秘钥交换方式，因此这个字段在TLS1.3中是没有实际作用的。

在ClientHello消息中，有一个重要的拓展，即`KeyShare`，用于与服务器交换秘钥。前文说到在TLS1.3中，ServerHello之后的所有消息都是加密的，那么为了双方能够正确加解密数据，因此在ClientHello中，客户端就已经通过该拓展告诉服务端自己的公钥以及秘钥交换算法，这里客户端还是指定了x25519椭圆曲线加密，并且生成一个临时私钥：
```
202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
```
对应的公钥计算方法前文已经说过
```shell
$ openssl pkey -noout -text &lt; client-ephemeral-private.key

X25519 Private-Key:
priv:
    20:21:22:23:24:25:26:27:28:29:2a:2b:2c:2d:2e:
    2f:30:31:32:33:34:35:36:37:38:39:3a:3b:3c:3d:
    3e:3f
pub:
    35:80:72:d6:36:58:80:d1:ae:ea:32:9a:df:91:21:
    38:38:51:ed:21:a2:8e:3b:75:e9:65:d0:d2:cd:16:
    62:54
```

如图所示

![](/posts/tls/ClientHello_tls1.3.png)

公钥就随着Client Hello发送给了服务端。

#### 3.1.2 **STEP 2**

##### 3.1.2.1 **Server Hello**

服务端根据客户端提供的选项，选择一个好自己支持的TLS版本以及加密套件，这里选的是`TLS_AES_256_GCM_SHA384`，生成的server_random：
```
707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f
```

由于涉及到了秘钥交换，服务端在收到请求后也需要先生成一对临时公私钥：
```
909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf
```
对应的公钥是:
```
9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615
```
`Key Share` Extension中返回的即为上述公钥

如果还记得上文的ECDH秘钥交换方法，就明白到这里服务端就可以很容易计算出两端的共享秘钥

```shell
$ ./curve25519-mult server-ephemeral-private.key \
                    client-ephemeral-public.key | hexdump

0000000 df 4a 29 1b aa 1e b7 cf a6 93 4b 29 b4 74 ba ad
0000010 26 97 e2 9f 1f 92 0d cc 77 c8 a0 a0 88 44 76 24
```

该秘钥用于生成后续握手包所需的秘钥，使用HKDF函数进行生成，如下所示

```c
early_secret = HKDF-Extract(salt: 00, key: 00...)
empty_hash = SHA384(&#34;&#34;)
derived_secret = HKDF-Expand-Label(key: early_secret, label: &#34;derived&#34;, ctx: empty_hash, len: 48)
handshake_secret = HKDF-Extract(salt: derived_secret, key: shared_secret)
client_secret = HKDF-Expand-Label(key: handshake_secret, label: &#34;c hs traffic&#34;, ctx: hello_hash, len: 48)
server_secret = HKDF-Expand-Label(key: handshake_secret, label: &#34;s hs traffic&#34;, ctx: hello_hash, len: 48)
client_handshake_key = HKDF-Expand-Label(key: client_secret, label: &#34;key&#34;, ctx: &#34;&#34;, len: 32)
server_handshake_key = HKDF-Expand-Label(key: server_secret, label: &#34;key&#34;, ctx: &#34;&#34;, len: 32)
client_handshake_iv = HKDF-Expand-Label(key: client_secret, label: &#34;iv&#34;, ctx: &#34;&#34;, len: 12)
server_handshake_iv = HKDF-Expand-Label(key: server_secret, label: &#34;iv&#34;, ctx: &#34;&#34;, len: 12)
```
得到以下秘钥：
- **handshake secret**: bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299
- **server handshake traffic secret**: 23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a68f481f2b019f9403a3051908a5d1622.
- **client handshake traffic secret**: db89d2d6df0e84fed74a2288f8fd4d0959f790ff23946cdf4c26d85e51bebd42ae184501972f8d30c4a3e4a3693d0ef0.
- **server handshake key**: 9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f
- **server handshake IV**: 9563bc8b590f671f488d2da3
- **client handshake key**: 1135b4826a9a70257e5a391ad93093dfd7c4214812f493b3e3daae1eb2b1ac69
- **client handshake IV**: 4256d2e0e88babdd05eb2f27

客户端也可以计算出同样的秘钥值。

![](/posts/tls/ServerHello_tls1.3.png)

##### 3.1.2.2 **Server Encrypted Extensions**

在计算完共享秘钥后，后续的流量将使用上述秘钥进行加密，因此对于TLS 1.2的情况服务端会先返回一个 ChangeCipherSpec，在TLS 1.3中可不必多此一举，不过在兼容模式下为了防止某些中间件抽风还是会多这么一步。

我们这里直接看加密的数据，服务端一般会先返回一个Encrypted Extensions类型的Record消息，该消息加密后存放在Record(type=0x17)，即Application Data的Body部分，同时(加密后数据的)末尾还添加了16字节的 **Auth Tag**，这是AEAD算法用来校验加密消息完整性的数据。

数据使用`AES-256-GCM`进行加密和校验，解密代码可以参考[aes_256_gcm_decrypt.c](https://tls13.ulfheim.net/files/aes_256_gcm_decrypt.c)，使用`server hanshake key/iv`进行解密的示例如下所示:
```shell
# server handshake key
$ key=9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f
# server handshake iv
$ iv=9563bc8b590f671f488d2da3
### from this record
$ recdata=1703030017
$ authtag=9ddef56f2468b90adfa25101ab0344ae
$ recordnum=0
### may need to add -I and -L flags for include and lib dirs
$ cc -o aes_256_gcm_decrypt aes_256_gcm_decrypt.c -lssl -lcrypto
$ echo &#34;6b e0 2f 9d a7 c2 dc&#34; | xxd -r -p &gt; /tmp/msg1
$ cat /tmp/msg1 \
  | ./aes_256_gcm_decrypt $iv $recordnum $key $recdata $authtag \
  | hexdump -C

00000000  08 00 00 02 00 00 16                              |.......|
```

这里解密后的拓展长度为空。一般与握手无关的额外拓展都会放在这里返回，这是为了能够尽可能地减少握手阶段的明文传输。

![](/posts/tls/ServerEncryptedExt.png)

##### 3.1.2.3 **Server Certificate**

使用server handshake key/iv进行加密。解密后的数据与TLS 1.2的证书响应相同。

![](/posts/tls/ServerCertificate_tls1.3.png)

##### 3.1.2.4 **Server Certificate Verify**

前文Hello阶段进行ECDHE秘钥交换的时候其实有个问题，即双方只交换了公钥，却没有认证这个秘钥，因此如果存在网络劫持，就可能被中间人进行攻击，那加密似乎也只是加了个寂寞。

但无需担心，这点早已在计划之中。虽然之前没有进行认证，但可以后面补上。Server Certificate Verify就是这个作用。该消息将服务端证书的私钥与之前生成的临时公钥进行绑定，准确来说是使用证书的私钥对其进行签名，并将签名算法与结果返回给客户端。由于客户端可以认证证书的有消息，就间接地证实了之前所交换的秘钥的真实性。

![](/posts/tls/ServerCertificateVerify_tls1.3.png)

##### 3.1.2.5 **Server Handshake Finished**

至此服务端所需要发送的握手包已经发送完毕了，因此最后发送一个Finished数据给客户端并等待对方的握手完成。在Finished数据中，消息体的内容和TLS1.2类似，是通过此前所有的握手数据计算得到的verify\_data，并使用HMAC进行认证，进一步确保此前的消息没有经过中间人修改。

计算方法如下:

```c
finished_key = HKDF-Expand-Label(key: server_secret, label: &#34;finished&#34;, ctx: &#34;&#34;, len: 32)
finished_hash = SHA384(Client Hello ... Server Cert Verify)
verify_data = HMAC-SHA384(key: finished_key, msg: finished_hash)
```

server\_secret是指前文中协商得到的server handshake traffic secret。

同时，服务端使用前面协商得到的handshake secret加上前面所有握手包的哈希重新计算出一个应用秘钥，用于加密实际的应用数据。计算方法如下:

```c
empty_hash = SHA384(&#34;&#34;)
derived_secret = HKDF-Expand-Label(key: handshake_secret, label: &#34;derived&#34;, ctx: empty_hash, len: 48)
master_secret = HKDF-Extract(salt: derived_secret, key: 00...)
client_secret = HKDF-Expand-Label(key: master_secret, label: &#34;c ap traffic&#34;, ctx: handshake_hash, len: 48)
server_secret = HKDF-Expand-Label(key: master_secret, label: &#34;s ap traffic&#34;, ctx: handshake_hash, len: 48)
client_application_key = HKDF-Expand-Label(key: client_secret, label: &#34;key&#34;, ctx: &#34;&#34;, len: 32)
server_application_key = HKDF-Expand-Label(key: server_secret, label: &#34;key&#34;, ctx: &#34;&#34;, len: 32)
client_application_iv = HKDF-Expand-Label(key: client_secret, label: &#34;iv&#34;, ctx: &#34;&#34;, len: 12)
server_application_iv = HKDF-Expand-Label(key: server_secret, label: &#34;iv&#34;, ctx: &#34;&#34;, len: 12)
```

之所以重新计算而不是使用handshake key是为了防止针对某些加密套件可能存在的选择密文攻击，最终得到了相当于TLS 1.2中的 client/server write key/IV。

- **server application key**: 01f78623f17e3edcc09e944027ba3218d57c8e0db93cd3ac419309274700ac27
- **server application IV**: 196a750b0c5049c0cc51a541
- **client application key**: de2f4c7672723a692319873e5c227606691a32d1c59d8b9f51dbb9352e9ca9cc
- **client application IV**: bb007956f474b25de902432f

相当于TLS 1.2中的client/server和write key/IV。

![](/posts/tls/ServerFinish.png)

#### 3.1.3 **STEP 3**

##### 3.1.3.1 **Client Handshake Finished**

由于双方的handshake secret相同，那么由此派生出来的application key/iv必然也是相同的。

客户端在收到Server Finished之后会使用对应服务器证书对数据进行校验，确认无误后进行可选的ChangeCipherSpec将加密并签名的verify\_data在Finished请求中发送给服务器。

```c
# client handshake traffic secret
finished_key = HKDF-Expand-Label(key: client_secret, label: &#34;finished&#34;, ctx: &#34;&#34;, len: 32)
finished_hash = SHA384(Client Hello ... Server Finished)
verify_data = HMAC-SHA384(key: finished_key, msg: finished_hash)
```

可以这么理解，Server Finished用来让客户端确认服务端没有被中间人攻击，而Client Finished则用来让服务端确认客户端没有被中间人攻击。双向认证之后则可以保证TLS握手的真实性和完整性，成功建立加密信道。

#### 3.1.4 **Server Session Ticket**

这一步通常是可选的。服务端在握手完成后会发送若干个ticket给客户端，可以理解为web中的cookie。客户端在后续如果需要重新发起握手，可以带上这个ticket，用于恢复当前的TLS会话。从上面的握手流程可见TLS握手需要涉及许多计算和网络请求，如果能够恢复会话，将极大地降低云服务器资源和网络延时。

ticket消息的格式如下：

```coffee
struct {
          uint32 ticket_lifetime;
          uint32 ticket_age_add;
          opaque ticket_nonce&lt;0..255&gt;;
          opaque ticket&lt;1..2^16-1&gt;;
          Extension extensions&lt;0..2^16-2&gt;;
      } NewSessionTicket;
```

包含有效期、随机数等信息。其中ticket字段对于客户端是透明的，但对于服务端而言需要是有效的会话凭据，可通过该数据恢复之前的TLS会话。

由于ticket是一次性的，综合考虑时间和空间成本，一般服务端都会返回两个ticket给客户端。由于是服务端返回的数据，因此使用server application key/iv进行加密。

![](/posts/tls/newTicket.png)

#### 3.1.5 **Application Data**

随后客户端发送的数据加密方式与handshake过程的加密类似，区别仅在于应用数据的加密使用的是client application key/iv，服务端发送给客户端的数据使用server application key/iv。

回顾之前的所有流程，再对比下图来巩固下

![](/posts/tls/TLSv1.3-handshake-1591540910347.png)

### 3.2 **1-RTT与0-RTT握手流程**

* 密钥计算的提前化（Early Data与PSK机制）。
* 0-RTT的安全争议与移动端应用限制（重放攻击风险）。

## 四、**协议组合变化的安全意义**

### 4.1 **密钥交换机制的演进**

* 从静态RSA到临时ECDHE（前向保密的强制化）。
* 加密与密钥交换的耦合关系（加密套件的AEAD化）。

### 4.2 **握手消息的加密范围**

* TLS 1.2的明文部分（Server Certificate） vs TLS 1.3的加密扩展（Encrypted Extensions）。

## 五、**逆向分析自定义协议的方法论提炼**

* **从TLS设计中学习的通用模式**：
  * ​握手阶段的标志性消息​（如随机数交换、密钥参数传递）。
  * ​密钥计算的时序依赖（何时生成加密密钥、如何验证完整性）。
* ​**自定义协议的常见漏洞点**：
  * 未加密的元数据暴露（如协议版本、支持的算法）。
  * 弱密钥交换逻辑（静态密钥复用、缺乏前向保密）。

## 六、**移动端TLS协议分析的实践挑战**

* **中间件干扰问题**：移动网络中的代理与TLS拦截（证书锁定绕过）。
* ​**协议混淆技术的干扰**：如何区分TLS握手与私有协议（流量特征分析）。

## 七、**结语**

### 7.1 **TLS协议分析的普适性价值**

* **逆向范式的标准化**

  TLS的分层设计（握手协议与记录协议解耦）和密钥派生流程（从随机数到会话密钥的确定性推导）为私有协议提供了标准范本。逆向分析人员可通过对比TLS的标准流程，快速定位私有协议中的“非常规”操作，例如：
  * 握手阶段未交换随机数（易遭受重放攻击）；
  * 密钥派生依赖静态参数（缺乏前向保密）；
  * 未加密的元数据暴露（如协议版本、设备指纹）。
* **攻击面的映射**

  TLS的历史漏洞（如FREAK、Logjam）本质上源于协议组合的缺陷（允许降级到弱算法）。类似地，私有协议若未强制加密算法或允许版本回滚，其攻击面可被快速锁定。

### 7.2 **从协议逆向到漏洞挖掘的方法论**

通过解构TLS，我们可提炼出逆向分析私有协议的**关键路径**：

1. **流程拆解**：
   * 识别握手阶段（类比TLS的`ClientHello/ServerHello`）与应用数据传输阶段（类比TLS记录协议）；
   * 标记明文与密文分界点（如TLS 1.3的`EncryptedExtensions`）。
2. ​**密钥追踪**：
   * 定位随机数生成点（如Hook `SecureRandom`类方法）；
   * 捕获密钥派生函数的输入输出（如拦截OpenSSL的`EVP_DigestSign`函数）。
3. ​**风险建模**：
   * 若协议未加密算法协商过程，可伪造降级请求（模拟TLS的`Downgrade Dance`攻击）；
   * 若协议复用会话密钥，可重放历史流量解密数据（类比TLS 1.2的Session Resumption漏洞）。

### 7.3 **后续思考**

* **工具化思维**：
  将TLS逆向方法论转化为自动化工具，例如：
  * 基于机器学习的协议指纹识别（从流量中分类TLS-like协议）；
  * 动态插桩框架（如Frida脚本库）快速提取密钥参数。
* ​**协作与知识沉淀**：
  建立私有协议的特征库（如常见随机数位置、密钥派生函数哈希类型），推动社区共享攻击面模型。

### **参考** 
1. [Swoole 源码分析——Server模块之OpenSSL(上)](https://github.com/LeoYang90/swoole-source-analysis/blob/master/Swoole%20%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90%E2%80%94%E2%80%94Server%E6%A8%A1%E5%9D%97%E4%B9%8BOpenSSL(%E4%B8%8A).md)
2. [深入浅出 SSL/TLS 协议](https://evilpan.com/2022/05/15/tls-basics/#application-data)

TLS协议是一面“镜子”，既映照出工业级协议应有的严谨性，也暴露出自定义协议在安全性上的妥协。作为移动安全工程师，我们应深入理解TLS的设计哲学，将其转化为逆向工程的“探针”——从随机数的生成到加密层的切换，每一步都可能成为击穿私有协议的突破口。唯有将协议逆向与安全设计原则深度融合，才能在隐私与安全的博弈中找到无往不胜的突破口。


---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/e319adc/  


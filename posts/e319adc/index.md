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
* `session_id`：主要用于恢复加密链接，需要客户端和服务端同时支持。由于秘钥协商的过程中涉及到很多费时的操作，对于短链接而言将之前协商好的加密通道恢复可以大大减少运算资源。如果服务器支持恢复会话，那么后续可以直接进入加密通信，否则还是需要进行完整的握手协商。该字段的长度是可变的，占1字节，也就是说数据部分最多可以长达255字节。
* `cipher_suites`：表示客户端所支持的加密套件，带有2字节长度字段，每个加密套件用2字节表示，且优先级高的排在前面。作用是和服务端协商加密算法，服务端根据支持算法在ServerHello返回一个最合适的算法组合。算法套件的格式为TLS\_密钥交换算法\_身份认证算法\_WITH\_对称加密算法\_消息摘要算法，比如`TLS_DHE_RSA_WITH_AES_256_CBC_SHA256`，密钥交换算法是`DHE`，身份认证算法是`RSA`，对称加密算法是AES\_256\_CBC，消息摘要算法是SHA256，由于RSA又可以用于加密也可以用于身份认证，因此密钥交换算法使用RSA时，只写一个RSA，比如`TLS_RSA_WITH_AES_256_CBC_SHA256`。
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
* `random`：逻辑和客户端相同
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
  
  
* `cipher_suites`：服务端根据客户端提供的算法套件列表和自己当前支持算法进行匹配，选择一个最合适的算法组合，若没有匹配项，则使用默认的`TLS_RSA_WITH_AES_128_CBC_SHA`。
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

如果使用了多级证书，那么返回的证书列表中第一个必须是对应域名的证书，而后每个证书都是前一个证书的 issuer，且最后一个证书是由系统中某个根证书签发的，注意根证书本身并不会一起返回。

如果服务端需要校验客户端证书的话，随后会发送一个`Certificate Request`请求，然后客户端返回对应的`Client Certificate`进行一轮额外的信息交换，当然这一步是可选的，从RFC的握手流程中也可以看出是这一步是可选的。

![](/posts/tls/ServerCertificate.png)

##### 2.1.2.3 **Server Key Exchange**

使用RSA公钥加密，必须要保证服务端私钥的安全。若私钥泄漏，则使用公钥加密的对称密钥就不再安全。同时RSA是基于大数因式分解。密钥位数必须足够大才能避免密钥被暴力破解。

&gt; 1999年，RSA-155 (512 bits) 被成功分解。
&gt; 2009年12月12日，RSA-768 (768 bits)也被成功分解。
&gt; 在2013年的棱镜门事件中，某个CA机构迫于美国政府压力向其提交了CA的私钥，这就是十分危险的。

相比之下，使用DH算法通过双方在不共享密钥的情况下双方就可以协商出共享密钥，避免了密钥的直接传输。DH算法是基于离散对数，计算相对较慢。而基于椭圆曲线密码（ECC）的DH算法计算速度更快，而且用更小的Key就能达到RSA加密的安全级别。ECC密钥长度为224\~225位几乎和RSA2048位具有相同的强度。

&gt; ECDH：基于ECC的DH算法。

简单来说，ECDH可以在通信媒介不可信的情况下安全地完成秘钥交换。假设A、B双方的公私钥分别是PA、SA，PB、SB，那么有

```
PA * SB == PB * SA
```

双方只需要知道对方的公钥，可以在不暴露私钥的情况下实现信息的交换，防止中间人攻击，所交换的信息就是后续使用的对称加密秘钥。

更进一步，为了避免未来私钥泄露导致以前的通信被解密，通常交换时并不直接使用原始公私钥，而是一个随机生成的新公私钥对，只需要用原始私钥进行认证。这种交换方式也称为ECDHE，其中 `E` 表示 `Ephemeral`，而这种做法所带来的称为`Forward Security`，即[前向安全](https://zh.wikipedia.org/wiki/%E5%89%8D%E5%90%91%E4%BF%9D%E5%AF%86)。

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
![](/posts/tls/ServerKeyExchange.png)

##### 2.1.2.4 **Server Hello Done**

当服务端处理Hello请求结束时，发送`Server Hello Done`消息，然后等待接收客户端握手消息。客户端收到服务端该消息，有必要时需要对服务端的证书进行有效性校验。`ServerHelloDone`无需数据。

```c
struct { } ServerHelloDone;
```

#### 2.1.3 **STEP 3**

##### 2.1.3.1 **Client Key Exchange**

客户端收到ClientKeyExchange后，得知服务器的方式生成临时密钥，ClientKeyExchange格式如下：

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

其格式相对简单，对于我们选择的加密套件而言只需要包含临时生成的ECDH公钥。注意此处与Server Key Exchange不同，并没有对客户端的公钥进行签名，也就是说可以被中间人进行替换。不过协议设计的时候已经考虑到了这一点，因为此时双方已经有足够的信息去协商秘钥并且进行验证了，通过后文的计算过程也可以确认这一点。

![](/posts/tls/ClientKeyExchange.png)

##### 2.1.3.2 **Client Change Cipher Spec**

该数据包告诉服务器客户端已经计算好了共享秘钥，并且后续客户端发送给服务器的数据都将使用共享秘钥进行加密。在**TLS1.3**中该数据包类型将会被移除，因为加密数据是可以通过数据类型推断的。

那么，客户端是如何计算出共享秘钥的呢？目前客户端所已知的数据为:

* client\_random
* server\_random
* server-ephemeral-public.key
* client-ephemeral-private.key

首先根据前文对ECDH的介绍，通过对方的公钥和自己的私钥，可以计算出一个共同秘钥，这里称之为`PMS(Pre-Master-Secret)`。该共享秘钥计算过程只涉及自身私钥和对方的公钥，为了进一步将共享秘钥关联当当前会话中，需要为其加入双方的随机数，当然不能直接相加，需要增加随机性，因此使用到了一个伪随机函数，称为 PRF(pseudorandom function)。其计算方式如下：

```
seed = &#34;master secret&#34; &#43; client_random &#43; server_random
a0 = seed
a1 = HMAC-SHA256(key=PreMasterSecret, data=a0)
a2 = HMAC-SHA256(key=PreMasterSecret, data=a1)
p1 = HMAC-SHA256(key=PreMasterSecret, data=a1 &#43; seed)
p2 = HMAC-SHA256(key=PreMasterSecret, data=a2 &#43; seed)
MasterSecret = p1[all 32 bytes] &#43; p2[first 16 bytes]
```

所得到的的 48 字节拓展秘钥称为主密钥(Master Secret)，在使用时需要将该主密钥进行拓展(至任意长度)，并将结果的不同部分分别用作不同秘钥：

```
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

最终秘钥分成了 6 个部分，分别是客户端和服务端的 MAC 秘钥、数据加密秘钥和初始向量。这里涉及到几个有趣的问题，比如：

* 为什么客户端和服务端要使用不同的数据加密秘钥？
* 为什么客户端和服务端要使用不同的 MAC 秘钥？
* 为什么要单独指定 IV？

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

为了进行验证，服务端使用相同的方式计算出共享秘钥`Pre Master Secret`，由ECDH的特性可以得知服务端和客户端计算出的`PMS`是相同的，因衍生出来的对称加密秘钥、IV、MAC秘钥也是相同的。

因此服务端收到加密数据后，可以使用协商出来的client\_write\_key对其进行解密，解密的值就是`cf919626f1360c536aaad73a`，同时原始数据末尾还有client mac key计算的签名，用于确保所接收数据的完整性。

这样服务端通过

* 将客户端发送的verify\_data与自身计算的值进行比对，可确保整个握手流程的完整性；
* 使用 HMAC 校验当前数据可以保证消息没有被中间人篡改。

在这些校验都完成后，服务端给客户端返回Change Cipher Spec消息，告知客户端接下来发送的数据都将经过协商秘钥进行加密。

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

`session_id`字段在此前的版本中该字段被用于恢复TLS会话，不过在TLS1.3中会话恢复使用了一种更为灵活的PSK秘钥交换方式，因此这个字段在TLS1.3中是没有实际作用的。

在ClientHello消息中，有一个重要的拓展，即`KeyShare`，用于与服务器交换秘钥。前文说到在TLS1.3中，ServerHello之后的所有消息都是加密的，那么为了双方能够正确加解密数据，因此在ClientHello中，客户端就已经通过该拓展告诉服务端自己的公钥以及秘钥交换算法，如图所示

![](/posts/tls/ClientHello_tls1.3.png)

客户端指定了x25519椭圆曲线加密，生成一对公私钥，该公钥就随着Client Hello发送给了服务端。

#### 3.1.2 **STEP 2**

##### 3.1.2.1 **Server Hello**

服务端根据客户端提供的选项，选择一个好自己支持的TLS版本以及加密套件，这里选的是`TLS_AES_256_GCM_SHA384`

由于涉及到了秘钥交换，服务端在收到请求后也需要先生成一对临时公私钥，`Key Share` Extension 中返回的即为上述公钥。

如果还记得上文的ECDH秘钥交换方法，就明白到这里服务端就可以很容易计算出两端的共享秘钥。该秘钥用于生成后续握手包所需的秘钥，使用HKDF函数进行生成，如下所示

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

![](/posts/tls/ServerHello_tls1.3.png)

##### 3.1.2.2 **Server Encrypted Extensions**

在计算完共享秘钥后，后续的流量将使用上述秘钥进行加密，因此对于TLS 1.2的情况服务端会先返回一个 ChangeCipherSpec，在TLS 1.3中可不必多此一举，不过在兼容模式下为了防止某些中间件抽风还是会多这么一步。

我们这里直接看加密的数据，服务端一般会先返回一个Encrypted Extensions类型的Record消息，该消息加密后存放在Record(type=0x17)，即Application Data的Body部分，同时(加密后数据的)末尾还添加了16字节的 **Auth Tag**，这是AEAD算法用来校验加密消息完整性的数据。

根据之前服务端所选择的套件，这里数据使用 `AES-256-GCM` 进行加密和校验，这里解密后的拓展长度为空。一般与握手无关的额外拓展都会放在这里返回，这是为了能够尽可能地减少握手阶段的明文传输。

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



TLS协议是一面“镜子”，既映照出工业级协议应有的严谨性，也暴露出自定义协议在安全性上的妥协。作为移动安全工程师，我们应深入理解TLS的设计哲学，将其转化为逆向工程的“探针”——从随机数的生成到加密层的切换，每一步都可能成为击穿私有协议的突破口。唯有将协议逆向与安全设计原则深度融合，才能在隐私与安全的博弈中找到无往不胜的突破口。


---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/e319adc/  


# 

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

整个流程目前只有`1RTT`，相比较之前的减少了一倍，在通信效率方面的提升巨大，而且还存在`0RTT`的模式，下面就通过具体的握手流程来分析下TLS1.3带来的变化

#### 3.1.1 STEP 1

##### 3.1.1.1 Client Hello

与TLS1.2一样，握手总是以Client发送Hello请求开始。但正如本节开头所说，TLS握手时的协议协商不再使用Handshake/Hello中的version字段，虽然是1.3版本，但请求中version还是指定1.2版本，这是因为有许多web中间件在设计时候会忽略不认识的TLS版本号，因此为了兼容性，版本号依旧保持不变。实际协商TLS版本是使用的是SupportedVersions拓展实现的。`ClientHello`的结构如下

```coffee
struct {
          ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
          Random random;
          opaque legacy_session_id&lt;0..32&gt;;
          CipherSuite cipher_suites&lt;2..2^16-2&gt;;
          opaque legacy_compression_methods&lt;1..2^8-1&gt;;
          Extension extensions&lt;8..2^16-1&gt;;
      } ClientHello;
```

`session_id`字段在此前的版本中该字段被用于恢复TLS会话，不过在TLS1.3中会话恢复使用了一种更为灵活的PSK秘钥交换方式，因此这个字段在TLS1.3中是没有实际作用的

在ClientHello消息中，有一个重要的拓展，即`KeyShare`，用于与服务器交换秘钥。前文说到在TLS1.3中，ServerHello之后的所有消息都是加密的，为了双方能够正确加解密数据，因此在ClientHello中通过该拓展告诉服务端自己的公钥以及秘钥交换算法

随后，该公钥就随着Client Hello发送给了服务端。

#### 3.1.2 STEP 2

##### 3.1.2.1 Server Hello

服务端根据客户端提供的选项，选择一个好自己支持的TLS版本以及加密套件，这里选的是`TLS_AES_256_GCM_SHA384`

由于涉及到了秘钥交换，服务端在收到请求后也需要先生成一对临时公私钥，`Key Share` Extension 中返回的即为上述公钥。

如果还记得上文的 ECDH 秘钥交换方法，这里就可以很容易计算出两端的共享秘钥。该秘钥用于生成后续握手包所需的秘钥，使用 HKDF 函数进行生成，如下所示

```coffee
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

##### 3.1.2.2 Server Encrypted Extensions

##### 3.1.2.3 Server Certificate

##### 3.1.2.4 Server Certificate Verify

##### 3.1.2.5 Server Handshake Finished

#### 3.1.3 STEP 3

##### 3.1.3.1 Client Handshake Finished

由于双方的handshake secret相同，那么由此派生出来的application key/iv必然也是相同的。

客户端在收到Server Finished之后会使用对应服务器证书对数据进行校验，确认无误后进行可选的ChangeCipherSpec将加密并签名的verify\_data在Finished请求中发送给服务器。

```coffee
# client handshake traffic secret
finished_key = HKDF-Expand-Label(key: client_secret, label: &#34;finished&#34;, ctx: &#34;&#34;, len: 32)
finished_hash = SHA384(Client Hello ... Server Finished)
verify_data = HMAC-SHA384(key: finished_key, msg: finished_hash)
```

可以这么理解，Server Finished用来让客户端确认服务端没有被中间人攻击，而Client Finished则用来让服务端确认客户端没有被中间人攻击。双向认证之后则可以保证TLS握手的真实性和完整性，成功建立加密信道。

#### 3.1.4 Application Data


---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/untitled/  


# 

上节中介绍了流量抓取的一些方案，对于常规 HTTP 流量而言没有太大争议，但是对于当今日趋普遍的 HTTPS 却有一些悬而未决的问题。如果我们抓到的所有 HTTPS 流量都是通过 TLS 进行加密的，那对于分析而言就几乎毫无价值了。

因此，为了能够对目标应用进行网络分析，应用层的私有加密姑且不论，至少要解决标准的 TLS 的解密问题。解密是为了中间人攻击，获取明文流量，那么就需要知道 TLS 中常规的中间人防御方案，一般来说，有下面几种:

1. 客户端验证服务端的证书链可信，基本操作；
2. 服务端验证客户端的证书可信(Certificate Request)，又称为双向证书绑定；
3. 客户端验证服务端的证书 HASH 是否在白名单中，即 SSL Pinning；
4. ……

在介绍后文的具体解密方案中也会围绕这几点去进行分析。

## 根证书

添加自定义的根证书应该是 HTTPS 流量分析的标准答案了。前文中提到的 Burpsuite、mitmproxy 等工具的文档中肯定都有介绍如何添加自定义根证书，根证书的存放对于不同的操作系统甚至不同的应用都有不同路径。比如在 Android 中，根证书存放在 `/system/etc/security/cacerts` 目录之下；在 iOS/macOS 中，根证书存放在 `Keychain` 中；对于 `Firefox` 浏览器，其应用中打包了证书链，不使用系统的证书。……

至于如何添加根证书，上过学的话应该都能在搜索引擎中找到方法，这里就不再啰嗦了。虽然添加自定义根证书可以让我们很方便地使用代理工具进行 HTTPS 流量分析，但其实际上只解决了第一个问题，因此对于某些做了额外校验的应用而言 TLS 握手还是无法成功的。

如果目标应用服务器在 TLS 握手中校验了客户端证书，那么我们还需要在代理工具中添加对应私钥才能顺利完成握手。该证书一般以 `p12` 格式存放，包含了客户端的证书及其私钥，通常还有一个额外的密码。通过逆向分析目标应用的的加载代码往往不难发现客户端证书的踪迹，甚至有时可以直接在资源文件中找到。

如果目标应用使用了 SSL Pinning 加固，那么通常是将服务器的证书 HASH 保存在代码中，并在握手**之后**进行额外校验。由于相关数据(证书HASH)和逻辑都在代码中，因此这种情况下往往只能通过侵入式的方式去绕过 Pinning 校验，比如 Patch 代码或者使用 hook 等方法实现。由于这是一个较为常见的功能，因此网上有很多相关脚本可以实现常规的 SSL Pinning bypass，但需要注意的是这并不意味着可以 100% 绕过，对于一些特殊实现仍然需要进行特殊分析。

## SSL keylog

除了在端侧添加自定义根证书，还有一种方式可以解密 SSL/TLS 的流量，即在握手过程中想办法获取到 TLS 会话的 `Master Key`，根据协商的加密套件，就可以对整个 TLS stream 进行解密。关于 TLS 握手的原理介绍，可以参考笔者上一篇文章 —— [深入浅出 SSL/TLS 协议](https://evilpan.com/2022/05/15/tls-basics/)。

知名的抓包和网络协议分析工具 `Wireshark` 就支持通过添加 `keylog` 文件去辅助 TLS 流量的解密。这里的 keylog 就是 [TLS 会话秘钥](https://wiki.wireshark.org/TLS)，文件格式为 [NSS Key Log Format](https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html)。对于不同版本的 TLS 内容略有不同，在 TLS 1.2 中只需要一个会话的 MasterKey，使用 `CLIENT_RANDOM` 去区分不同会话；而在 TLS 1.3 中每个会话包含 5 个秘钥，分别用于解密握手、数据阶段的不同数据。

那么，这个 keylog 文件我们应该如何获取呢？对于大部分 SSL 库而言，比如 OpenSSL、BoringSSL、libreSSL 等，都可以通过 [SSL\_CTX\_set\_keylog\_callback](https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_keylog_callback.html) 这个 API 去设置获取的回调，令 SSL 库在握手成功后调用对应的回调函数从而获取 keylog。因此我们就需要通过静态 patch 或者动态 hook 的方式去为 TLS 添加该回调。

这看似很简单，但实际操作起来会遇到一些问题。比如，很多大型商业应用都封装了自己的 SSL 库，甚至同一个应用中不同组件中又间接包含了有多个 SSL 库，为了每一个 TLS 会话都能成功解密，需要确保每个 SSL 库都要被正确 patch 或者 hook；

其次，对于某些组件而言，实际是通过静态编译的方式引入 SSL 库，比如 `webview`、`libflutter`、`libffmpeg` 等。在去除掉符号后，我们可能需要通过一些方法去搜索定位所需的符号地址。这个任务的难度可大可小，简单的可以通过 yara、Bindiff 去进行定位，复杂的话也可以通过一些深度学习算法去进行相似度分析，比如科恩的 `BinaryAI` 或者阿里云的 `Finger` 等。感兴趣的也可以去进一步阅读相关的综述文章:

&gt; [USENIX Security 2022 - How Machine Learning Is Solving the Binary Function Similarity Problem](https://www.eurecom.fr/publication/6847/download/sec-publi-6847.pdf)

另外还有一个问题，`SSL_CTX_set_keylog_callback` 这个 API 并不是最初就存在于 SSL 库中的。以 openssl 为例，keylog 文件的支持实际上是在 commit [4bf73e](https://github.com/openssl/openssl/commit/4bf73e9f86804cfe98b03accfc2dd7cb98e018d6) 中才被引入。因此，如果遇到了某些应用中依赖于旧版本的 SSL 库，那么可能就不支持 keylog。我们要想强行支持就要进行二进制级别的 cherry-pick，这个工作量还是挺大的。

虽然有这些那些难点，但这种解密方法的一大优点是可以一次性解决本节开头所提及的三个问题，即服务端证书校验、客户端证书校验和 SSL Pinning。因为该方法并没有对流量进行网络层面的中间人，而是在应用的运行过程中泄露会话秘钥，因此不会影响上层的证书校验。

## SSL read/write

既然设置 keylog 如此麻烦，为什么不找一些相对简单且通用的 API 去进行解密呢？一个直接的思路就是通过挂钩 [SSL\_read](https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html)、SSL\_write 来获取 SSL 读写的明文数据。基于这个思路目前网上有许多工程化的实现，比如 [eCapture](https://github.com/ehids/ecapture) 是基于 `eBPF/uprobes` 的 TLS 抓包方案；[r0capture](https://github.com/r0ysue/r0capture) 则是基于 `frida` 注入的 TLS 抓包方案。

使用该方法进行解密的一大优点，或者说特点，是这种方式可以在解密的同时直接输出明文信息，因此可以完全略过**流量抓取**这一步。虽然许多开源工具是将结果保存为 pcap 文件进行进一步分析的，但实际上也可以直接在标准输出或者日志文件中打印出来进行分析。

由于这些抓包工具本质上都是在获取 SSL read/write 明文的基础上再以 pcap 格式进行转储，因此同样会面临 keylog 方案所面临的问题，即依赖 SSL 库的符号。但不同的是其所依赖的是较为通用的符号，因此不太会受到 SSL 库版本的限制。唯一需要考虑的难题是如何解析无符号的 SSL 库中相关函数的偏移地址，这在上节中有些简单介绍，展开的话又是另一篇论文了。



上述介绍的每一种流量抓取方法都可以和任意一种流量解密方法相结合，组成一种网络流量分析方案。实践上使用较多的是下面几种组合:

* 系统 HTTP 代理 &#43; 根证书
* 路由抓包/透明代理 &#43; 根证书
* tcpdump &#43; keylog
* SSL\_read/SSL\_write hook

每种方案都有其优点和缺点:

| 抓包方案             | 优点                 | 缺点                               |
| ---------------- | ------------------ | -------------------------------- |
| 系统代理             | 配置简单，工具成熟          | 可被忽略，流量不全，证书问题                   |
| 路由抓包             | 流量完整，应用透明          | 配置复杂，协议受限，证书问题                   |
| tcpdump &#43; keylog | 流量完整，无需证书协议丰富，应用过滤 | TLS 解密需要 hook 应用且依赖于 SSL 库的版本和符号 |
| SSL read/write   | 劫持简单，无需证书          | 需要(某些)符号，依赖 hook，流量不全            |

那么实际安全分析中要如何选择呢？正如那句老话所说: **网络安全没有银弹**，实际情况也无法一概而论，通常是根据具体的目标去进行分析。

例如，对于操作系统比较封闭的 IoT 设备，通过路由抓包是唯一选择；对于移动应用或者桌面应用而言，可以先尝试传统的系统代理方式，添加对应根证书，如果不能抓到包，可以通过流量分析可能的问题:

* 流量日志中服务端有 Certificate Request 则表示进行了客户端证书校验；
* 流量日志中握手成功但很快断开，则客户端中可能使用了 SSL Pinning 加固；
* 流量日志中客户端握手失败，Alert 提示证书不可信，则说明客户端使用了自定义的 keystore 而不是系统的根证书；
* ……


---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/untitled/  


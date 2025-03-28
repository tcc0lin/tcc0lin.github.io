# 终端流量对抗的经验总结


&lt;!--more--&gt;

在移动端逆向工程领域，网络流量分析始终是攻防博弈的核心战场。作为安全研究人员，网络流量是破解应用行为逻辑的关键突破口，分析者需要运用多层级抓包技术（数据链路层WiFi热点镜像、传输层tcpdump全流量捕获、应用层Charles/Fiddler MITM攻击）还原通信全貌，通过解析HTTPS握手过程、API调用时序、数据加密特征等关键信息，逆向推导出客户端加密算法、接口鉴权机制等风控系统核心逻辑。

面对日益严峻的黑产威胁，主流应用已构建起多维防御体系：在协议层面强制SSL Pinning锁定证书链，结合双向证书校验阻断代理工具中间人攻击；采用私有二进制协议封装数据，在TLS加密层之上叠加动态密钥协商机制，使传统抓包工具难以直接解析明文；不断升级的网络协议（QUIC），在提升传输效率的同时也持续提升协议分析的门槛。

因此，合理有效的终端流量对抗将会极大提升逆向分析的效率，让安全研究人员可以更加专注投入的代码分析中，下面是笔者在分析众多`Android` app协议的过程中所使用的工具迭代及尝试总结的经验。

## 一、网络流量形态分析

在展开技术论述前，需首先明确网络流量的典型形态。若排除物理层射频信号分析、硬件调试接口（如JTAG）等特殊场景，商业环境中的网络通信多基于通用协议栈构建。

早期以HTTP为代表的明文传输协议因易受运营商劫持、中间人攻击等风险，已逐渐被TLS加密技术取代，成为现代网络隐私保护的核心机制。尽管HTTP协议持续迭代（如HTTP/1.1、HTTP/2及厂商定制的QUIC协议），其本质仍属于传输层与应用层协议的范畴。

对于安全研究而言，无论是流量抓取（如抓包技术）还是协议解析（如解密与逆向工程），均需突破协议封装与加密逻辑的双重屏障。下文将基于流量捕获与协议解析两大技术维度，系统剖析攻防对抗的核心路径。

## 二、流量抓取

对应我们日常所说的“抓包”。

### 2.1 系统代理

这是最为简单也是最为常用的一种抓包方案，也是大多数人在接触抓包时最初接触到的方案。在Android、iOS、macOS这些操作系统中连接WiFi时可以指定我们自定义的HTTP代理地址。如果应用使用了是系统提供的网络库或者遵循这个代理配置，那么就会将HTTP(S)请求通过该代理进行发送。

#### 2.1.1 原理

以`Android11`代码为例，当我们在这么操作：**设置→WLAN→长按具体的WIFI名→修改网络→手动代理或自动代理**之后，最终会调用到`ConnectivityService`的`updateLinkProperties`函数

```java
// file: packages/modules/Connectivity/service/src/com/android/server/ConnectivityService.java
public void updateLinkProperties(NetworkAgentInfo networkAgent, @NonNull LinkProperties newLp,
            @NonNull LinkProperties oldLp) {
    //...
    if (isDefaultNetwork(networkAgent)) {
        handleApplyDefaultProxy(newLp.getHttpProxy());
    } else {
        updateProxy(newLp, oldLp);
    }
}
```

最终会进入执行更新代理的操作，这里判断了当前更新的网络是否是默认（正在使用的网络），如果是则需要将此代理设置为默认代理，否则只通知更新即可。

```java
// file: packages/modules/Connectivity/service/src/com/android/server/connectivity/ProxyTracker.java
public void sendProxyBroadcast() {
    final ProxyInfo defaultProxy = getDefaultProxy();
    final ProxyInfo proxyInfo = null != defaultProxy ? defaultProxy : new ProxyInfo(&#34;&#34;, 0, &#34;&#34;);
    if (mPacManager.setCurrentProxyScriptUrl(proxyInfo) == PacManager.DONT_SEND_BROADCAST) {
        return;
    }
    if (DBG) Slog.d(TAG, &#34;sending Proxy Broadcast for &#34; &#43; proxyInfo);
    Intent intent = new Intent(Proxy.PROXY_CHANGE_ACTION);
    intent.addFlags(Intent.FLAG_RECEIVER_REPLACE_PENDING |
            Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
    intent.putExtra(Proxy.EXTRA_PROXY_INFO, proxyInfo);
    final long ident = Binder.clearCallingIdentity();
    try {
        mContext.sendStickyBroadcastAsUser(intent, UserHandle.ALL);
    } finally {
        Binder.restoreCallingIdentity(ident);
    }
}
```

通知代理更新时主要工作是发送了`PROXY_CHANGE_ACTION`的广播，而这个类型的广播在AMS中注册

```java
// file: frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java
case Proxy.PROXY_CHANGE_ACTION:
    mHandler.sendMessage(mHandler.obtainMessage(UPDATE_HTTP_PROXY_MSG));
    break;
case UPDATE_HTTP_PROXY_MSG: {
        mProcessList.setAllHttpProxy();
    } break;

// file: frameworks/base/services/core/java/com/android/server/am/ProcessList.java
void setAllHttpProxy() {
    // Update the HTTP proxy for each application thread.
    synchronized (mService) {
        for (int i = mLruProcesses.size() - 1 ; i &gt;= 0 ; i--) {
            ProcessRecord r = mLruProcesses.get(i);
            // Don&#39;t dispatch to isolated processes as they can&#39;t access ConnectivityManager and
            // don&#39;t have network privileges anyway. Exclude system server and update it
            // separately outside the AMS lock, to avoid deadlock with Connectivity Service.
            if (r.pid != ActivityManagerService.MY_PID &amp;&amp; r.thread != null &amp;&amp; !r.isolated) {
                try {
                    r.thread.updateHttpProxy();
                } catch (RemoteException ex) {
                    Slog.w(TAG, &#34;Failed to update http proxy for: &#34;
                            &#43; r.info.processName);
                }
            }
        }
    }
    ActivityThread.updateHttpProxy(mService.mContext);
}

// file: frameworks/base/core/java/android/app/ActivityThread.java
public static void updateHttpProxy(@NonNull Context context) {
      final ConnectivityManager cm = ConnectivityManager.from(context);
      Proxy.setHttpProxySystemProperty(cm.getDefaultProxy());
  }
```

广播处理的结果是调用到`Proxy`类中设置代理

```java
// file: frameworks/base/core/java/android/net/Proxy.java
public static final void setHttpProxySystemProperty(String host, String port, String exclList,
        Uri pacFileUrl) {
    if (exclList != null) exclList = exclList.replace(&#34;,&#34;, &#34;|&#34;);
    if (false) Log.d(TAG, &#34;setHttpProxySystemProperty :&#34;&#43;host&#43;&#34;:&#34;&#43;port&#43;&#34; - &#34;&#43;exclList);
    if (host != null) {
        System.setProperty(&#34;http.proxyHost&#34;, host);
        System.setProperty(&#34;https.proxyHost&#34;, host);
    } else {
        System.clearProperty(&#34;http.proxyHost&#34;);
        System.clearProperty(&#34;https.proxyHost&#34;);
    }
    if (port != null) {
        System.setProperty(&#34;http.proxyPort&#34;, port);
        System.setProperty(&#34;https.proxyPort&#34;, port);
    } else {
        System.clearProperty(&#34;http.proxyPort&#34;);
        System.clearProperty(&#34;https.proxyPort&#34;);
    }
    if (exclList != null) {
        System.setProperty(&#34;http.nonProxyHosts&#34;, exclList);
        System.setProperty(&#34;https.nonProxyHosts&#34;, exclList);
    } else {
        System.clearProperty(&#34;http.nonProxyHosts&#34;);
        System.clearProperty(&#34;https.nonProxyHosts&#34;);
    }
    if (!Uri.EMPTY.equals(pacFileUrl)) {
        ProxySelector.setDefault(new PacProxySelector());
    } else {
        ProxySelector.setDefault(sDefaultProxySelector);
    }
}
```

从代码中可以看到，设置系统代理底层最终调用到的是`System.setProperty(&#34;http.proxyHost&#34;, host);`

那么除了手动设置以外，还可以通过adb shell直接设置代理，例如

```shell
# 代理设置
adb shell settings put global http_proxy &lt;代理IP&gt;:&lt;端口&gt;
# 代理生效验证
adb shell settings get global http_proxy
# 清除代理
adb shell settings put global http_proxy null
```

当设置好代理后，App发起请求时系统会对`Host`和`Port`进行替换
```java
// file: external/okhttp/okhttp/src/main/java/com/squareup/okhttp/internal/http/RouteSelector.java
private void resetNextInetSocketAddress(Proxy proxy) throws IOException {
    // Clear the addresses. Necessary if getAllByName() below throws!
    inetSocketAddresses = new ArrayList&lt;&gt;();

    String socketHost;
    int socketPort;
    if (proxy.type() == Proxy.Type.DIRECT || proxy.type() == Proxy.Type.SOCKS) {
      socketHost = address.getUriHost();
      socketPort = address.getUriPort();
    } else {
      SocketAddress proxyAddress = proxy.address();
      if (!(proxyAddress instanceof InetSocketAddress)) {
        throw new IllegalArgumentException(
            &#34;Proxy.address() is not an &#34; &#43; &#34;InetSocketAddress: &#34; &#43; proxyAddress.getClass());
      }
      InetSocketAddress proxySocketAddress = (InetSocketAddress) proxyAddress;
      socketHost = getHostString(proxySocketAddress);
      socketPort = proxySocketAddress.getPort();
    }
    ...
  }
```

#### 2.1.2 使用方式

由于系统代理通常只能拦截到HTTP(S)类型的流量，因此大部分都是配合传统抓包软件Burpsuite、Fiddler、Charles这类的工具使用，由其作为代理服务器，将设备流量转发到代理服务器上。

整体上配置简单，且对于流量的格式化、重放攻击、代码转化都已经优化的十分贴合用户，也成为大部分安全研究人员的第一任工具。当然，对于非HTTP的其他协议支持可能就不是很完善了。

#### 2.1.3 防御与对抗

本质上系统代理是`Android`提供的一个代理机制，就好比AOSP和三方厂商一样，&#34;规范&#34;和&#34;实际&#34;是两回事，因此也带来了这种方式的一个最明显的缺点：应用可能不按规矩来。不管是设置的系统代理，还是通过 `HTTP_PROXY` 环境变量指定代理，都只是一种**约定俗成**的规则而已。很多网络库都提供了额外的配置选项来让App可以指定或者忽略任何系统代理，例如

* **okhttp**
  ```
  var mOkHttpClientBuilder = OkHttpClient.Builder().proxy(Proxy.NO_PROXY)
  ```
* **HttpURLConnection** 
  ```
  httpurlconnection.openconnection(Proxy.NO_PROXY)
  ```

原理是当请求失败时会调用`httpEngine.recover`将失败的`proxy`加入`RouteSelector`内并对请求进行重试，而重试时因为之前已经将`proxy`加入黑名单中，因此可以直接进行请求，不走代理。

```java
// file: external/okhttp/okhttp/src/main/java/com/squareup/okhttp/internal/http/RouteSelector.java
public Route next() throws IOException {
  // Compute the next route to attempt.
  if (!hasNextInetSocketAddress()) {
    if (!hasNextProxy()) {
      if (!hasNextPostponed()) {
        throw new NoSuchElementException();
      }
      return nextPostponed();
    }
    lastProxy = nextProxy();
  }
  lastInetSocketAddress = nextInetSocketAddress();

  Route route = new Route(address, lastProxy, lastInetSocketAddress);
  if (routeDatabase.shouldPostpone(route)) {
    postponedRoutes.add(route);
    // We will only recurse in order to skip previously failed routes. They will be tried last.
    return next();
  }

  return route;
}
```

另一方面某些风控SDK会通过主动检测`http.proxyHost`和`https.proxyPort`等属性来判断系统是否使用了系统代理从而完成对这种方式的绕过。

从上文可以看出来由于系统提供了App绕过代理的方式，因此仅仅是基于系统代理的方式并不能保证抓取到完整的流量，除了主动分析hook掉之外还可以选择其他的抓取方式。

### 2.2 虚拟网卡VPN

既然在应用层的系统代理会很轻易地被App绕过，那就继续下钻深入的传输层、数据链路层试试，这里所使用的技术是虚拟网卡，也就是通常所说的&#34;VPN&#34;

VPN实现原理就是在本地运行一个**虚拟专用网络**，构建一个虚拟网卡设备，并将路由规则修改为优先通过我们虚拟的网卡进行请求。比如，Android上可以通过实现VPNService去构建自己的VPN服务，postern就是一个很直观的案例，不过postern没有开源，可以另外参考[NetBare-Android](https://github.com/MegatronKing/NetBare-Android)的实现。

#### 2.2.1 原理

VpnService是开发Android VPN的基础，下面是[官方文档](https://developer.android.com/reference/android/net/VpnService)的阐释

&gt; VpnService is a base class for applications to extend and build their own VPN solutions. In general, it creates a virtual network interface, configures addresses and routing rules, and returns a file descriptor to the application. Each read from the descriptor retrieves an outgoing packet which was routed to the interface. Each write to the descriptor injects an incoming packet just like it was received from the interface. The interface is running on Internet Protocol (IP), so packets are always started with IP headers. The application then completes a VPN connection by processing and exchanging packets with the remote server over a tunnel.

上面的阐释的重点是：

* 创建​**虚拟网络接口**​（虚拟网卡），负责捕获和注入网络数据包。
* 接口基于**IP协议**，数据包始终以IP头开始。

官方也提供了Example：[ToyVpn](https://android.googlesource.com/platform/development/&#43;/master/samples/ToyVpn)，概述就是调用VpnService类的`establish()`方法会获取到一个fd，通过读取fd就能获取到ip数据报文。

简单从源码角度来看看

```java
// file: frameworks/base/core/java/android/net/VpnService.java
public ParcelFileDescriptor establish() {
    mConfig.addresses = mAddresses;
    mConfig.routes = mRoutes;

    try {
        return getService().establishVpn(mConfig);
    } catch (RemoteException e) {
        throw new IllegalStateException(e);
    }
}
```

调用了ConnectivityService 这个系统服务的 `establishVpn(mConfig)`方法

```java
// file: frameworks/base/services/core/java/com/android/server/ConnectivityService.java
protected final SparseArray&lt;Vpn&gt; mVpns = new SparseArray&lt;&gt;();

/**
  * Configure a TUN interface and return its file descriptor. Parameters
  * are encoded and opaque to this class. This method is used by VpnBuilder
  * and not available in ConnectivityManager. Permissions are checked in
  * Vpn class.
  * @hide
  */
 @Override
 public ParcelFileDescriptor establishVpn(VpnConfig config) {
     int user = UserHandle.getUserId(Binder.getCallingUid());
     synchronized (mVpns) {
         throwIfLockdownEnabled();
         return mVpns.get(user).establish(config);
     }
 }
```

选择具体Vpn对象来处理

```java
// file: frameworks/base/services/core/java/com/android/server/connectivity/Vpn.java
public synchronized ParcelFileDescriptor establish(VpnConfig config) {
      // Check if the caller is already prepared.
      // Check to ensure consent hasn&#39;t been revoked since we were prepared.
      // Check if the service is properly declared.
      ...
      // Configure the interface. Abort if any of these steps fails.
      ParcelFileDescriptor tun = ParcelFileDescriptor.adoptFd(jniCreate(config.mtu));
      try {
          String interfaze = jniGetName(tun.getFd());

          // TEMP use the old jni calls until there is support for netd address setting
          StringBuilder builder = new StringBuilder();
          for (LinkAddress address : config.addresses) {
              builder.append(&#34; &#34;);
              builder.append(address);
          }
          if (jniSetAddresses(interfaze, builder.toString()) &lt; 1) {
              throw new IllegalArgumentException(&#34;At least one address must be specified&#34;);
          }
          Connection connection = new Connection();
          if (!mContext.bindServiceAsUser(intent, connection,
                  Context.BIND_AUTO_CREATE | Context.BIND_FOREGROUND_SERVICE,
                  new UserHandle(mUserHandle))) {
              throw new IllegalStateException(&#34;Cannot bind &#34; &#43; config.user);
          }

          ...

          // Set up forwarding and DNS rules.
          // First attempt to do a seamless handover that only changes the interface name and
          // parameters. If that fails, disconnect.
          if (oldConfig != null
                  &amp;&amp; updateLinkPropertiesInPlaceIfPossible(mNetworkAgent, oldConfig)) {
              // Keep mNetworkAgent unchanged
          } else {
              mNetworkAgent = null;
              updateState(DetailedState.CONNECTING, &#34;establish&#34;);
              // Set up forwarding and DNS rules.
              agentConnect();
          }

          ...
      } catch (RuntimeException e) {
          ...
      }
      Log.i(TAG, &#34;Established by &#34; &#43; config.user &#43; &#34; on &#34; &#43; mInterface);
      return tun;
  }
```

忽略重重的`check`函数之后，关键在于`jniCreate`创建了fd

```c
//file: frameworks/base/services/core/jni/com_android_server_connectivity_Vpn.cpp 
static const JNINativeMethod gMethods[] = {
    {&#34;jniCreate&#34;, &#34;(I)I&#34;, (void *)create},
    {&#34;jniGetName&#34;, &#34;(I)Ljava/lang/String;&#34;, (void *)getName},
    {&#34;jniSetAddresses&#34;, &#34;(Ljava/lang/String;Ljava/lang/String;)I&#34;, (void *)setAddresses},
    {&#34;jniReset&#34;, &#34;(Ljava/lang/String;)V&#34;, (void *)reset},
    {&#34;jniCheck&#34;, &#34;(Ljava/lang/String;)I&#34;, (void *)check},
    {&#34;jniAddAddress&#34;, &#34;(Ljava/lang/String;Ljava/lang/String;I)Z&#34;, (void *)addAddress},
    {&#34;jniDelAddress&#34;, &#34;(Ljava/lang/String;Ljava/lang/String;I)Z&#34;, (void *)delAddress},
};

static jint create(JNIEnv *env, jobject /* thiz */, jint mtu)
{
    int tun = create_interface(mtu);
    if (tun &lt; 0) {
        throwException(env, tun, &#34;Cannot create interface&#34;);
        return -1;
    }
    return tun;
}

static int create_interface(int mtu)
{
    int tun = open(&#34;/dev/tun&#34;, O_RDWR | O_NONBLOCK | O_CLOEXEC);

    ifreq ifr4;
    memset(&amp;ifr4, 0, sizeof(ifr4));

    ...

    // Set MTU if it is specified.
    ifr4.ifr_mtu = mtu;
    if (mtu &gt; 0 &amp;&amp; ioctl(inet4, SIOCSIFMTU, &amp;ifr4)) {
        ALOGE(&#34;Cannot set MTU on %s: %s&#34;, ifr4.ifr_name, strerror(errno));
        goto error;
    }

    return tun;

error:
    close(tun);
    return SYSTEM_ERROR;
}
```

最终所做的操作是打开了`/dev/tun`这个文件，设置mtu并返回fd（和官方所描述的一样）。

**那么什么是tun呢?**

`tap/tun`是Linux内核2.4.x版本之后实现的虚拟网络设备，不同于物理网卡，`tap/tun`虚拟网卡完全由软件来实现，功能和硬件实现完全没有差别，它们同属于网络设备，可以配置IP，都归Linux网络设备管理模块统一管理。唯一的差异在于

* tap是一个二层设备（或者以太网设备），只能处理二层的以太网帧；
* tun是一个点对点的三层设备（或网络层设备），只能处理三层的IP数据包。

作为网络设备，tap/tun也需要配套相应的驱动程序才能工作。tap/tun驱动程序包括两个部分，一个是字符设备驱动，一个是网卡驱动。这两部分驱动程序分工不太一样，字符驱动负责数据包在内核空间和用户空间的传送，网卡驱动负责数据包在TCP/IP网络协议栈上的传输和处理。

`tap/tun`对应的字符设备文件分别为：

* tap：/dev/tap0
* tun：/dev/tun0

设备文件即充当了用户空间和内核空间通信的接口。当应用程序打开设备文件时，驱动程序就会创建并注册相应的虚拟设备接口，一般以`tunX`或`tapX`命名。当应用程序关闭文件时，驱动也会自动删除`tunX`和`tapX`设备，还会删除已经建立起来的路由等信息。

`tap/tun`设备文件就像一个管道，一端连接着用户空间，一端连接着内核空间。当用户程序向文件`/dev/net/tun`或`/dev/tap0`写数据时，内核就可以从对应的`tunX`或`tapX`接口读到数据，反之，内核可以通过相反的方式向用户程序发送数据。

**VPN对于网络数据的影响**

参考[网络虚拟化技术（二）: TUN/TAP MACVLAN MACVTAP](https://www.cnblogs.com/yudar/p/4630958.html)，先来看看物理网卡是如何工作的：


![](/posts/packet/vpn1.png)

正常的网卡通过网线来收发数据包，所有物理网卡收到的数据包会交给内核的Network Stack处理，然后通过Socket API通知给用户程序。

看看tun的工作方式

![](/posts/packet/vpn2.png)

但是tun设备通过一个`/dev/tunX`文件收发数据包。所有对该文件的写操作会通过tun设备转换成一个数据包送给内核；当内核发送一个包给tun设备时，通过读这个文件可以拿到包的内容。

如果我们使用tun设备搭建一个基于`UDP VPN`，那么整个处理过程就是这样：

![](/posts/packet/vpn3.png)

数据包会通过内核网络栈两次。但是经过App的处理后，数据包可能已经加密，并且原有的ip头被封装在udp内部，所以第二次通过网络栈内核看到的是截然不同的网络包。

tap/tun通过实现相应的网卡驱动程序来和网络协议栈通信。一般的流程和物理网卡和协议栈的交互流程是一样的，不同的是物理网卡一端是连接物理网络，而tap/tun虚拟网卡一般连接到用户空间。

**一个简单的案例**

```
&#43;----------------------------------------------------------------&#43;
|                                                                |
|  &#43;--------------------&#43;      &#43;--------------------&#43;            |
|  | User Application A |      | User Application B |&lt;-----&#43;     |
|  &#43;--------------------&#43;      &#43;--------------------&#43;      |     |
|               | 1                    | 5                 |     |
|...............|......................|...................|.....|
|               ↓                      ↓                   |     |
|         &#43;----------&#43;           &#43;----------&#43;              |     |
|         | socket A |           | socket B |              |     |
|         &#43;----------&#43;           &#43;----------&#43;              |     |
|                 | 2               | 6                    |     |
|.................|.................|......................|.....|
|                 ↓                 ↓                      |     |
|             &#43;------------------------&#43;                 4 |     |
|             | Newwork Protocol Stack |                   |     |
|             &#43;------------------------&#43;                   |     |
|                | 7                 | 3                   |     |
|................|...................|.....................|.....|
|                ↓                   ↓                     |     |
|        &#43;----------------&#43;    &#43;----------------&#43;          |     |
|        |      eth0      |    |      tun0      |          |     |
|        &#43;----------------&#43;    &#43;----------------&#43;          |     |
|    10.32.0.11  |                   |   192.168.3.11      |     |
|                | 8                 &#43;---------------------&#43;     |
|                |                                               |
&#43;----------------|-----------------------------------------------&#43;
                 ↓
         Physical Network
```

上图中有两个应用程序A和B，都在用户层，而其它的socket、协议栈（Newwork Protocol Stack）和网络设备（eth0和tun0）部分都在内核层，其实socket是协议栈的一部分，这里分开来的目的是为了看的更直观。

tun0是一个Tun/Tap虚拟设备，从上图中可以看出它和物理设备eth0的差别，它们的一端虽然都连着协议栈，但另一端不一样，eth0的另一端是物理网络，这个物理网络可能就是一个交换机，而tun0的另一端是一个用户层的程序，协议栈发给tun0的数据包能被这个应用程序读取到，并且应用程序能直接向tun0写数据。

上图中有两个应用程序A和B，都在用户层，而其它的socket、协议栈（Newwork Protocol Stack）和网络设备（eth0和tun0）部分都在内核层，其实socket是协议栈的一部分，这里分开来的目的是为了看的更直观。

tun0是一个Tun/Tap虚拟设备，从上图中可以看出它和物理设备eth0的差别，它们的一端虽然都连着协议栈，但另一端不一样，eth0的另一端是物理网络，这个物理网络可能就是一个交换机，而tun0的另一端是一个用户层的程序，协议栈发给tun0的数据包能被这个应用程序读取到，并且应用程序能直接向tun0写数据。

这里假设eth0配置的IP是`10.32.0.11`，而tun0配置的IP是`192.168.3.11`.

&gt;这里列举的是一个典型的tun/tap设备的应用场景，发到192.168.3.0/24网络的数据通过程序B这个隧道，利用10.32.0.11发到远端网络的10.33.0.1，再由10.33.0.1转发给相应的设备，从而实现VPN。

下面来看看数据包的流程：

1. 应用程序A是一个普通的程序，通过socket A发送了一个数据包，假设这个数据包的目的IP地址是192.168.3.1
2. socket将这个数据包丢给协议栈
3. 协议栈根据数据包的目的IP地址，匹配本地路由规则，知道这个数据包应该由tun0出去，于是将数据包交给tun0
4. tun0收到数据包之后，发现另一端被进程B打开了，于是将数据包丢给了进程B
5. 进程B收到数据包之后，做一些跟业务相关的处理，然后构造一个新的数据包，将原来的数据包嵌入在新的数据包中，最后通过socket B将数据包转发出去，这时候新数据包的源地址变成了eth0的地址，而目的IP地址变成了一个其它的地址，比如是10.33.0.1.
6. socket B将数据包丢给协议栈
7. 协议栈根据本地路由，发现这个数据包应该要通过eth0发送出去，于是将数据包交给eth0
8. eth0通过物理网络将数据包发送出去

10.33.0.1收到数据包之后，会打开数据包，读取里面的原始数据包，并转发给本地的192.168.3.1，然后等收到192.168.3.1的应答后，再构造新的应答包，并将原始应答包封装在里面，再由原路径返回给应用程序B，应用程序B取出里面的原始应答包，最后返回给应用程序A

从上面的流程中可以看出，数据包选择走哪个网络设备完全由路由表控制，所以如果我们想让某些网络流量走应用程序B的转发流程，就需要配置路由表让这部分数据走tun0。

#### 2.2.2 使用方式

使用方式有两种思路

1. 设备本地VPN抓包解析：数据包直接在本地解析，不转发到额外的服务器，无需利用其他设备，分析简单直接。

2. 设备本地VPN抓包-转发外部服务器解析：和本地解析相比，指定VPN服务器一般都是主机/服务器的形式，拥有更强的数据处理能力且支持多台设备统一处理，常见的方案是`Charles`&#43;`Postern`，由Charles在PC端建立socket服务器，Postern在本地建立VPN拦截数据包转发到Charles上，Charles又可以提供实时解析数据包的能力（VPN软件不受限，像大部分翻墙软件都可以）。

#### 2.2.3 防御与对抗

由于VPN是基于系统实现的网络层流量拦截，因此普通App对这种行为的反抗能力几乎是没有（无法强制流量绕过），但是由于这种实现是基本VPN方案的，因此比较有效的对抗方式是检测VPN。

### 2.3 网关（路由）

相比于在设备上实现虚拟网卡的方案存在明显的VPN特征来说，在设备外的网关层（路由）进行抓包可以完美的实现设备无感知。

#### 2.3.1 原理

#### 2.3.2 使用方式

使用方式的思路主要区别在于确定路由器是什么，例如下列这几种常见的方案：

1. 普通PC都会自带无线网卡，基于PC端开启的热点作为路由器，让设备连接该热点，再通过`Wireshark`指定无线网卡进行抓包

2. 使用类似360随身WiFi，插到PC上提供热点功能，再通过`Wireshark`指定无线网卡进行抓包

3. 将闲置的PC或者路由器刷成Openwrt系统，使用`tcpdump`指定无线网卡进行抓包

4. [使用树莓派3B打造超强路由](https://gist.github.com/snakevil/7d7af1d8ca2c739e3fedc5b15eb8e4aa)

#### 2.3.3 防御与对抗

单从防御流量抓取维度上来说无法对抗

### 2.4 libpcap

在前文中网关（路由）抓包和虚拟网卡抓包的方式中，都可以使用`tcpdump`进行抓包，前者需要指定网卡为热点网卡（AP），后者指定为虚拟网卡（TUN）即可。这样抓包出来的结果是一个`pcap`文件，一般直接丢到`Wireshark`里面去进行分析。与前面的方法相比，这种方法对于`HTTP`的可视化解析可能相对简陋，但是对于协议类型的支持却非常广泛，基本上你能叫出名字的标准协议都可以进行解析。

`tcpdump`本质上是基于`libpcap`实现的

#### 2.4.1 原理

libpcap主要由两部份组成：**网络分接头(Network Tap)**和**数据过滤器(Packet Filter)**。
- 网络分接头从网络设备驱动中收集数据拷贝
- 过滤器决定是否接收该数据包

网络分接头从网络设备驱动程序（`NIC driver`）中收集数据拷贝，过滤器决定是否接收该数据包。`libpcap`利用`BSD Packet Filter`（也就是通常说的`BPF`）对网卡接收到的链路层数据包进行过滤。

![](/posts/packet/libpcap1.png)

从整体流程中可以看出`libpcap`的两个部分

**Network Tap**

`libpcap`是数据链路层`PF_PACKET`协议的标准实现，向网卡驱动注册一个`PF_PACKET`类型的socket，后续就可以持续的从该socket中获取到网卡驱动分发的数据包，而且从图中也可以看出，`PF_PACKET`类型和正常的`PF_INET`类型是有差异的，`PF_INET`主要服务于系统网络协议栈，`PF_PACKET`类型作为旁路流量处理，支持独立于系统网络栈单独处理流量。

![](/posts/packet/libpcap3.png)

**Packet Filter**

`Packet Filter`在内核层根据指定规则利用BPF机制完成数据包的过滤，使用共享内存方式，在内核空间中分配一块内核缓冲区，然后用户空间程序调用mmap映射到用户空间完成数据包的读取。

![](/posts/packet/libpcap2.png)

#### 2.4.2 使用方式

可以参考[协议特征提取](https://tcc0lin.github.io/posts/e319adc/#512-%E5%AE%8C%E5%85%A8%E8%87%AA%E7%A0%94%E5%8D%8F%E8%AE%AE%E7%9A%84%E8%AE%BE%E8%AE%A1%E7%89%B9%E5%BE%81)中提及到的针对App uid抓包的方式可以过滤掉非目标流量的干扰

#### 2.4.3 防御与对抗

单从防御流量抓取维度上来说无法对抗

## 三、协议解析

## 总结

## 参考

1. [Android4.4 wifi代理流程](https://bbs.kanxue.com/thread-252161-1.htm#msg_header_h2_2)
2. [【Android】 使用VPN实现抓包](https://itimetraveler.github.io/2019/07/25/%E3%80%90Android%E3%80%91%E4%BD%BF%E7%94%A8VPN%E5%AE%9E%E7%8E%B0%E6%8A%93%E5%8C%85/#TUN-TAP%E6%98%AF%E4%BB%80%E4%B9%88)
3. [图解linux tcpdump](https://jgsun.github.io/2019/01/21/linux-tcpdump/)
4. [网卡多队列绑定中断的方式优化网络吞吐
](https://blog.csdn.net/sdgdsczs/article/details/129365078)

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/19081ef/  


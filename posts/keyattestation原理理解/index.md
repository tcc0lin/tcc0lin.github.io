# KeyAttestation原理理解


结合github项目[KeyAttestation](https://github.com/vvb2060/KeyAttestation)来学习KeyAttestation原理
### 一、项目结构
#### 1.1 App展示
![](https://raw.githubusercontent.com/tcc0lin/picx-images-hosting/master/WechatIMG55.86tl7csurn.webp)
![](https://github.com/tcc0lin/picx-images-hosting/raw/master/WechatIMG54.8z6gp39h1y.webp)
页面展示来自于attestationResult这个回调结果
```java
// app/src/main/java/io/github/vvb2060/keyattestation/home/HomeViewModel.kt

val useStrongBox = hasStrongBox &amp;&amp; preferStrongBox
val includeProps = hasDeviceIds &amp;&amp; preferIncludeProps
val useAttestKey = hasAttestKey &amp;&amp; preferAttestKey
val result = try {
    val attestationResult = doAttestation(useStrongBox, includeProps, useAttestKey)
    Resource.success(attestationResult)
} catch (e: Throwable) {
    val cause = if (e is AttestationException) e.cause else e
    Log.w(AppApplication.TAG, &#34;Do attestation error.&#34;, cause)

    when (e) {
        is AttestationException -&gt; Resource.error(e, null)
        else -&gt; Resource.error(AttestationException(CODE_UNKNOWN, e), null)
    }
}
```
#### 1.2 初步梳理流程
```java
// app/src/main/java/io/github/vvb2060/keyattestation/home/HomeViewModel.kt

@Throws(AttestationException::class)
private fun doAttestation(useStrongBox: Boolean,
                            includeProps: Boolean,
                            useAttestKey: Boolean): AttestationResult {
    val certs = ArrayList&lt;Certificate&gt;()
    val alias = if (useStrongBox) &#34;${AppApplication.TAG}_strongbox&#34; else AppApplication.TAG
    val attestKeyAlias = if (useAttestKey) &#34;${alias}_persistent&#34; else null
    try {
        // 1. generateKey
        if (useAttestKey &amp;&amp; !keyStore.containsAlias(attestKeyAlias)) {
            generateKey(attestKeyAlias!!, useStrongBox, includeProps, attestKeyAlias)
        }
        generateKey(alias, useStrongBox, includeProps, attestKeyAlias)

        // 2. certs collect
        val certChain = keyStore.getCertificateChain(alias)
                ?: throw CertificateException(&#34;Unable to get certificate chain&#34;)
        for (cert in certChain) {
            val buf = ByteArrayInputStream(cert.encoded)
            certs.add(certificateFactory.generateCertificate(buf))
        }
        if (useAttestKey) {
            val persistChain = keyStore.getCertificateChain(attestKeyAlias)
                    ?: throw CertificateException(&#34;Unable to get certificate chain&#34;)
            for (cert in persistChain) {
                val buf = ByteArrayInputStream(cert.encoded)
                certs.add(certificateFactory.generateCertificate(buf))
            }
        }
    } catch (e: ProviderException) {
        // 异常流程，可忽略
        ......
    } catch (e: Exception) {
        throw AttestationException(CODE_UNKNOWN, e)
    }
    @Suppress(&#34;UNCHECKED_CAST&#34;)
    // 3. parseCertificateChain
    currentCerts = certs as List&lt;X509Certificate&gt;
    return parseCertificateChain(certs)
}
```
从代码流程中可以分为三步
1. generateKey
2. certs collect
3. parseCertificateChain
### 二、源码分析
#### 2.1 入参
doAttestation的入参有三个
- useStrongBox
- includeProps
- useAttestKey

获取方式是
```java
// android.hardware.strongbox_keystore
useStrongBox = pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
// android.hardware.keystore.app_attest_key
hasAttestKey = pm.hasSystemFeature(PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY)
hasDeviceIds = pm.hasSystemFeature(&#34;android.software.device_id_attestation&#34;)
```
是从PackageManager中获取系统属性，这三个属性指的是什么意思呢？这里需要引入[Android KeyStore](https://source.android.com/docs/security/features/keystore?hl=zh-cn)的演变历史

KeyStore是借助系统芯片 (SoC) 中提供的可信执行环境，由硬件支持的密钥库

1. KeyMaster 0.2 0.3
&gt;在 Android 6.0 之前的版本中，Android 已有一个非常简单的由硬件支持的加密服务 API（由 0.2 和 0.3 版的 Keymaster 硬件抽象层 (HAL) 提供）。该密钥库能够提供数字签名和验证操作，以及不对称签名密钥对的生成和导入操作。该 API 在许多设备上都已实现，但有许多安全目标无法只通过一个签名 API 来轻松达成。Android 6.0 中的密钥库在该密钥库 API 的基础上进行了扩展，能够提供更广泛的功能
2. KeyMaster 1
&gt;在 Android 6.0 中，密钥库不仅增加了对称加密基元（AES 和 HMAC），还增加了针对由硬件支持的密钥的访问权限控制系统。访问权限控制在密钥生成期间指定，并会在密钥的整个生命周期内被强制执行。可以将密钥限定为仅在用户通过身份验证后才可使用，并且只能用于指定的目的或只有在具有指定的加密参数时才可使用。如需了解详情，请参阅授权标记和函数页面。
3. KeyMaster 2
&gt;在 Android 7.0 中，Keymaster 2 增加了对密钥认证和版本绑定的支持。密钥认证提供公钥证书，这些证书中包含密钥及其访问权限控制的详细描述，以使密钥存在于安全硬件中并使其配置可以远程验证。
4. KeyMaster 3
&gt;在 Android 8.0 中，Keymaster 3 从旧式 C 结构硬件抽象层 (HAL) 转换到根据新硬件接口定义语言 (HIDL) 中的定义生成的 C&#43;&#43; HAL 接口。在此变更过程中，很多参数类型发生了变化，但这些类型和方法与旧的类型和 HAL 结构体方法一一对应。如需了解详情，请参阅函数页面
&gt;
&gt;除了此接口修订之外，Android 8.0 还扩展了 Keymaster 2 的认证功能，以支持 ID 认证。 ID 认证提供了一种受限且可选的机制来严格认证硬件标识符，例如设备序列号、产品名称和手机 ID (IMEI/MEID)。为了实现此新增功能，Android 8.0 更改了 ASN.1 认证架构，添加了 ID 认证。Keymaster 实现需要通过某种安全方式来检索相关的数据项，还需要定义一种安全永久地停用该功能的机制。
5. KeyMaster 4
&gt;Android 9 纳入了以下更新：
&gt;更新到 Keymaster 4
对嵌入式安全元件的支持
对安全密钥导入的支持
对 3DES 加密的支持
更改了版本绑定，以便 boot.img 和 system.img 分别设置版本以允许独立更新

从KeyStore的版本演变上看，在迭代过程中逐步加入了新的认证方式，而FEATURE_STRONGBOX_KEYSTORE、FEATURE_KEYSTORE_APP_ATTEST_KEY就是判断设备是否支持某种认证方式（原因是因为OEM厂商不一定会紧跟着Google的架构演变方案）

#### 2.2 generateKey
```java
if (useAttestKey &amp;&amp; !keyStore.containsAlias(attestKeyAlias)) {
    generateKey(attestKeyAlias!!, useStrongBox, includeProps, attestKeyAlias)
}
generateKey(alias, useStrongBox, includeProps, attestKeyAlias)
```
这里区分了生成key的类型，如果设备开启了App Attest Key特性的话生成的密钥可以用来做密钥认证（Key Attestation），否则就是正常的数字签名密钥
这里优先根据是否开启了App Attest Key特性及KeyStore中是否包含attestKeyAlias的密钥来进行密钥生成
```java
private fun generateKey(alias: String,
                        useStrongBox: Boolean,
                        includeProps: Boolean,
                        attestKeyAlias: String?) {
    val now = Date()
    val attestKey = alias == attestKeyAlias
    // 密钥用途判定
    val purposes = if (Build.VERSION.SDK_INT &gt;= Build.VERSION_CODES.S &amp;&amp; attestKey) {
        KeyProperties.PURPOSE_ATTEST_KEY
    } else {
        KeyProperties.PURPOSE_SIGN
    }
    // 设置 KeyGenParameterSpec
    val builder = KeyGenParameterSpec.Builder(alias, purposes)
            .setAlgorithmParameterSpec(ECGenParameterSpec(&#34;secp256r1&#34;))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setCertificateNotBefore(now)
            .setAttestationChallenge(now.toString().toByteArray())
    if (Build.VERSION.SDK_INT &gt;= Build.VERSION_CODES.P &amp;&amp; useStrongBox) {
        builder.setIsStrongBoxBacked(true)
    }
    if (Build.VERSION.SDK_INT &gt;= Build.VERSION_CODES.S) {
        if (includeProps) {
            builder.setDevicePropertiesAttestationIncluded(true)
        }
        if (attestKey) {
            builder.setCertificateSubject(X500Principal(&#34;CN=App Attest Key&#34;))
        } else {
            builder.setAttestKeyAlias(attestKeyAlias)
        }
    }
    // 获取 KeyPairGenerator 实例
    val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, &#34;AndroidKeyStore&#34;)
    // 用 KeyGenParameterSpec 初始化 KeyPairGenerator
    keyPairGenerator.initialize(builder.build())
    // 生成密钥对
    keyPairGenerator.generateKeyPair()
}
```
此时，KeyStore中包含了名称为alias的密钥对

#### 2.3 certs collect
```java
val certChain = keyStore.getCertificateChain(alias)
        ?: throw CertificateException(&#34;Unable to get certificate chain&#34;)
for (cert in certChain) {
    val buf = ByteArrayInputStream(cert.encoded)
    certs.add(certificateFactory.generateCertificate(buf))
}
if (useAttestKey) {
    val persistChain = keyStore.getCertificateChain(attestKeyAlias)
            ?: throw CertificateException(&#34;Unable to get certificate chain&#34;)
    for (cert in persistChain) {
        val buf = ByteArrayInputStream(cert.encoded)
        certs.add(certificateFactory.generateCertificate(buf))
    }
}
```
在上一步生成key之后根据alias获取到对应的证书链，证书链是一个认证过程，最终指向可信的根证书，因此获取到的证书链实际的形式是
&gt;终端证书-&gt;中间证书-&gt;根证书
#### 2.4 parseCertificateChain
```java
// app/src/main/java/io/github/vvb2060/keyattestation/attestation/CertificateInfo.java

public static AttestationResult parseCertificateChain(List&lt;X509Certificate&gt; certs) {
    var infoList = new ArrayList&lt;CertificateInfo&gt;();

    // 在certs中最后一个指向的是终端证书，逐步向上遍历
    var parent = certs.get(certs.size() - 1);
    for (int i = certs.size() - 1; i &gt;= 0; i--) {
        var parentKey = parent.getPublicKey();
        var info = new CertificateInfo(certs.get(i));
        infoList.add(info);
        info.checkStatus(parentKey);
        if (parent == info.cert) {
            info.checkIssuer();
        } else {
            parent = info.cert;
        }
        if (info.checkAttestation()) {
            break;
        }
    }

return AttestationResult.form(infoList);
```
遍历证书列表，进行三次校验
- checkStatus
- checkIssuer
- checkAttestation
##### 2.4.1 checkStatus
```java 
// app/src/main/java/io/github/vvb2060/keyattestation/attestation/CertificateInfo.java

private void checkStatus(PublicKey parentKey) {
    try {
        status = CERT_SIGN;
        cert.verify(parentKey);
        status = CERT_REVOKED;
        var certStatus = RevocationList.get(cert.getSerialNumber());
        if (certStatus != null) {
            throw new CertificateException(&#34;Certificate revocation &#34; &#43; certStatus);
        }
        status = CERT_EXPIRED;
        cert.checkValidity();
        status = CERT_NORMAL;
    } catch (GeneralSecurityException e) {
        securityException = e;
    }
}
```
在checkStatus函数中存在状态流转的过程，涉及到两个函数verify、checkValidity，主要目的是为了确保一个证书的签名是有效的、且被信任的上级证书所签发

##### 2.4.2 checkIssuer
```java
// app/src/main/java/io/github/vvb2060/keyattestation/attestation/CertificateInfo.java

private void checkIssuer() {
    var publicKey = cert.getPublicKey().getEncoded();
    if (Arrays.equals(publicKey, googleKey)) {
        issuer = KEY_GOOGLE;
    } else if (Arrays.equals(publicKey, aospEcKey)) {
        issuer = KEY_AOSP;
    } else if (Arrays.equals(publicKey, aospRsaKey)) {
        issuer = KEY_AOSP;
    } else if (Arrays.equals(publicKey, knoxSakv2Key)) {
        issuer = KEY_KNOX;
    } else if (oemKeys != null) {
        for (var key : oemKeys) {
            if (Arrays.equals(publicKey, key.getEncoded())) {
                issuer = KEY_OEM;
                break;
            }
        }
    }
}
```
这一步是为了确定根证书的颁发机构，其中获取OEM Key的方式如下
```java
private static Set&lt;PublicKey&gt; getOemPublicKey() {
    var resName = &#34;android:array/vendor_required_attestation_certificates&#34;;
    var res = AppApplication.app.getResources();
    // noinspection DiscouragedApi
    var id = res.getIdentifier(resName, null, null);
    if (id == 0) {
        return null;
    }
    var set = new HashSet&lt;PublicKey&gt;();
    try {
        var cf = CertificateFactory.getInstance(&#34;X.509&#34;);
        for (var s : res.getStringArray(id)) {
            var cert = s.replaceAll(&#34;\\s&#43;&#34;, &#34;\n&#34;)
                    .replaceAll(&#34;-BEGIN\\nCERTIFICATE-&#34;, &#34;-BEGIN CERTIFICATE-&#34;)
                    .replaceAll(&#34;-END\\nCERTIFICATE-&#34;, &#34;-END CERTIFICATE-&#34;);
            var input = new ByteArrayInputStream(cert.getBytes());
            var publicKey = cf.generateCertificate(input).getPublicKey();
            set.add(publicKey);
        }
    } catch (CertificateException e) {
        Log.e(AppApplication.TAG, &#34;getOemKeys: &#34;, e);
        return null;
    }
    set.removeIf(key -&gt; Arrays.equals(key.getEncoded(), googleKey));
    if (set.isEmpty()) {
        return null;
    }
    set.forEach(key -&gt; Log.i(AppApplication.TAG, &#34;getOemKeys: &#34; &#43; key));
    return set;
}
```
##### 2.4.3 checkAttestation
```java
// app/src/main/java/io/github/vvb2060/keyattestation/attestation/CertificateInfo.java

private boolean checkAttestation() {
    boolean terminate;
    try {
        attestation = Attestation.loadFromCertificate(cert);
        // If key purpose included KeyPurpose::SIGN,
        // then it could be used to sign arbitrary data, including any tbsCertificate,
        // and so an attestation produced by the key would have no security properties.
        // If the parent certificate can attest that the key purpose is only KeyPurpose::ATTEST_KEY,
        // then the child certificate can be trusted.
        var purposes = attestation.getTeeEnforced().getPurposes();
        terminate = purposes == null || !purposes.contains(AuthorizationList.KM_PURPOSE_ATTEST_KEY);
    } catch (CertificateParsingException e) {
        certException = e;
        terminate = false;
        checkProvisioningInfo();
    }
    return terminate;
}

// app/src/main/java/io/github/vvb2060/keyattestation/attestation/Attestation.java

public static Attestation loadFromCertificate(X509Certificate x509Cert) throws CertificateParsingException {
    if (x509Cert.getExtensionValue(EAT_OID) == null
            &amp;&amp; x509Cert.getExtensionValue(ASN1_OID) == null) {
        throw new CertificateParsingException(&#34;No attestation extensions found&#34;);
    }
    if (x509Cert.getExtensionValue(EAT_OID) != null) {
        if (x509Cert.getExtensionValue(ASN1_OID) != null) {
            throw new CertificateParsingException(&#34;Multiple attestation extensions found&#34;);
        }
        try {
            return new EatAttestation(x509Cert);
        } catch (CborException cbe) {
            throw new CertificateParsingException(&#34;Unable to parse EAT extension&#34;, cbe);
        }
    }
    if (x509Cert.getExtensionValue(CRL_DP_OID) != null) {
        Log.w(AppApplication.TAG,
                &#34;CRL Distribution Points extension found in leaf certificate.&#34;);
    }
    if (x509Cert.getExtensionValue(KNOX_OID) != null) {
        return new KnoxAttestation(x509Cert);
    }
    return new Asn1Attestation(x509Cert);
}
```
根据代码逻辑的理解，是根据证书颁发机构来选择各自的认证方式
###### 2.4.3.1 EatAttestation
EatAttestation使用实体认证令牌 (Entity Attestation Token, EAT) 进行设备认证。EAT是一种基于IETF标准的轻量级认证格式，场景更多的是存在嵌入到IoT设备中
###### 2.4.3.2 KnoxAttestation
三星电子提供的一种设备认证和安全机制，核心逻辑还是走的Asn1
###### 2.4.3.3 Asn1Attestation
重点关注下Asn1的认证方式，也是官方选择的认证方式，参考文档[security-key-attestation](https://developer.android.com/privacy-and-security/security-key-attestation?hl=zh-cn#verifying)
```java
// app/src/main/java/io/github/vvb2060/keyattestation/attestation/Asn1Attestation.java

public Asn1Attestation(X509Certificate x509Cert) throws CertificateParsingException {
    super(x509Cert);
    ASN1Sequence seq = getAttestationSequence(x509Cert);

    attestationVersion =
            Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(ATTESTATION_VERSION_INDEX));
    attestationSecurityLevel =
            Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(ATTESTATION_SECURITY_LEVEL_INDEX));
    keymasterVersion = Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(KEYMASTER_VERSION_INDEX));
    keymasterSecurityLevel =
            Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(KEYMASTER_SECURITY_LEVEL_INDEX));

    attestationChallenge =
            Asn1Utils.getByteArrayFromAsn1(seq.getObjectAt(ATTESTATION_CHALLENGE_INDEX));

    uniqueId = Asn1Utils.getByteArrayFromAsn1(seq.getObjectAt(UNIQUE_ID_INDEX));

    softwareEnforced = new AuthorizationList(seq.getObjectAt(SW_ENFORCED_INDEX));
    teeEnforced = new AuthorizationList(seq.getObjectAt(TEE_ENFORCED_INDEX));
}
```
根据传入的x509Cert解析成各个字段，这里可以参考[ASN.1架构](https://source.android.com/docs/security/features/keystore/attestation?hl=zh-cn#attestation-extension)
```
KeyDescription ::= SEQUENCE {
  attestationVersion         INTEGER, # KM2 value is 1. KM3 value is 2. KM4 value is 3.
  attestationSecurityLevel   SecurityLevel,
  keymasterVersion           INTEGER,
  keymasterSecurityLevel     SecurityLevel,
  attestationChallenge       OCTET_STRING,
  uniqueId                   OCTET_STRING,
  softwareEnforced           AuthorizationList,
  teeEnforced                AuthorizationList,
}

SecurityLevel ::= ENUMERATED {
  Software                   (0),
  TrustedEnvironment         (1),
  StrongBox                  (2),
}

AuthorizationList ::= SEQUENCE {
  purpose                     [1] EXPLICIT SET OF INTEGER OPTIONAL,
  algorithm                   [2] EXPLICIT INTEGER OPTIONAL,
  keySize                     [3] EXPLICIT INTEGER OPTIONAL.
  digest                      [5] EXPLICIT SET OF INTEGER OPTIONAL,
  padding                     [6] EXPLICIT SET OF INTEGER OPTIONAL,
  ecCurve                     [10] EXPLICIT INTEGER OPTIONAL,
  rsaPublicExponent           [200] EXPLICIT INTEGER OPTIONAL,
  rollbackResistance          [303] EXPLICIT NULL OPTIONAL, # KM4
  activeDateTime              [400] EXPLICIT INTEGER OPTIONAL
  originationExpireDateTime   [401] EXPLICIT INTEGER OPTIONAL
  usageExpireDateTime         [402] EXPLICIT INTEGER OPTIONAL
  noAuthRequired              [503] EXPLICIT NULL OPTIONAL,
  userAuthType                [504] EXPLICIT INTEGER OPTIONAL,
  authTimeout                 [505] EXPLICIT INTEGER OPTIONAL,
  allowWhileOnBody            [506] EXPLICIT NULL OPTIONAL,
  trustedUserPresenceRequired [507] EXPLICIT NULL OPTIONAL, # KM4
  trustedConfirmationRequired [508] EXPLICIT NULL OPTIONAL, # KM4
  unlockedDeviceRequired      [509] EXPLICIT NULL OPTIONAL, # KM4
  allApplications             [600] EXPLICIT NULL OPTIONAL,
  applicationId               [601] EXPLICIT OCTET_STRING OPTIONAL,
  creationDateTime            [701] EXPLICIT INTEGER OPTIONAL,
  origin                      [702] EXPLICIT INTEGER OPTIONAL,
  rollbackResistant           [703] EXPLICIT NULL OPTIONAL, # KM2 and KM3 only.
  rootOfTrust                 [704] EXPLICIT RootOfTrust OPTIONAL,
  osVersion                   [705] EXPLICIT INTEGER OPTIONAL,
  osPatchLevel                [706] EXPLICIT INTEGER OPTIONAL,
  attestationApplicationId    [709] EXPLICIT OCTET_STRING OPTIONAL, # KM3
  attestationIdBrand          [710] EXPLICIT OCTET_STRING OPTIONAL, # KM3
  attestationIdDevice         [711] EXPLICIT OCTET_STRING OPTIONAL, # KM3
  attestationIdProduct        [712] EXPLICIT OCTET_STRING OPTIONAL, # KM3
  attestationIdSerial         [713] EXPLICIT OCTET_STRING OPTIONAL, # KM3
  attestationIdImei           [714] EXPLICIT OCTET_STRING OPTIONAL, # KM3
  attestationIdMeid           [715] EXPLICIT OCTET_STRING OPTIONAL, # KM3
  attestationIdManufacturer   [716] EXPLICIT OCTET_STRING OPTIONAL, # KM3
  attestationIdModel          [717] EXPLICIT OCTET_STRING OPTIONAL, # KM3
  vendorPatchLevel            [718] EXPLICIT INTEGER OPTIONAL, # KM4
  bootPatchLevel              [719] EXPLICIT INTEGER OPTIONAL, # KM4
}

RootOfTrust ::= SEQUENCE {
  verifiedBootKey            OCTET_STRING,
  deviceLocked               BOOLEAN,
  verifiedBootState          VerifiedBootState,
  verifiedBootHash           OCTET_STRING, # KM4
}

VerifiedBootState ::= ENUMERATED {
  Verified                   (0),
  SelfSigned                 (1),
  Unverified                 (2),
  Failed                     (3),
}
```
checkAttestation的核心是
```java
// app/src/main/java/io/github/vvb2060/keyattestation/attestation/CertificateInfo.java

// If key purpose included KeyPurpose::SIGN,
// then it could be used to sign arbitrary data, including any tbsCertificate,
// and so an attestation produced by the key would have no security properties.
// If the parent certificate can attest that the key purpose is only KeyPurpose::ATTEST_KEY,
// then the child certificate can be trusted.
var purposes = attestation.getTeeEnforced().getPurposes();
terminate = purposes == null || !purposes.contains(AuthorizationList.KM_PURPOSE_ATTEST_KEY);

// app/src/main/java/io/github/vvb2060/keyattestation/attestation/AuthorizationList.java

public AuthorizationList(ASN1Encodable asn1Encodable) throws CertificateParsingException {
    if (!(asn1Encodable instanceof ASN1Sequence sequence)) {
        throw new CertificateParsingException(&#34;Expected sequence for authorization list, found &#34;
                &#43; asn1Encodable.getClass().getName());
    }
    for (var entry : sequence) {
        if (!(entry instanceof ASN1TaggedObject taggedObject)) {
            throw new CertificateParsingException(
                    &#34;Expected tagged object, found &#34; &#43; entry.getClass().getName());
        }
        int tag = taggedObject.getTagNo();
        var value = taggedObject.getBaseObject().toASN1Primitive();
        switch (tag) {
            default:
                throw new CertificateParsingException(&#34;Unknown tag &#34; &#43; tag &#43; &#34; found&#34;);

            case KM_TAG_PURPOSE &amp; KEYMASTER_TAG_TYPE_MASK:
                purposes = Asn1Utils.getIntegersFromAsn1Set(value);
                break;
        }
    }
}
```
核心是要证明teeEnforced的purpose字段，根据上面那段注释我理解是将密钥用途分为了签名和认证
1. 签名用途 (KeyPurpose::SIGN)：
如果密钥的用途包含签名，那么它可以对任意数据进行签名。这种情况下，持有该密钥的实体可以签名任何数据，包括认证证书自身 (tbsCertificate)。若如此，这个密钥生成的认证就没有任何实际的安全保证，因为任何人都可以在任意数据上应用该签名，伪装成合法的认证。签名的真实性无法被保障
2. 认证用途 (KeyPurpose::ATTEST_KEY)：
如果密钥用途被正确设定为仅用于认证 (KeyPurpose::ATTEST_KEY)，那么该密钥只能用于生成认证证书，而不能用于签名任意数据。在这种情况下，父证书可以证明子证书的密钥用途仅限于认证，从而确保子证书的可信度。这种可信度依赖于父证书的有效性，也就是根证书的可信度

这里引入了认证的源头：根证书的可信度问题
Andorid通过[Trusty TEE](https://source.android.com/docs/security/features/trusty?hl=zh-cn)完成证书的存储，TEE在硬件层面解决了安全性问题，其中类似RootOfTrust这类数据都是由厂商在设备出产时烧录到硬件存储当中的，从根本上解决了根密钥不可信的问题，并以此根密钥为信任链根，派生密钥

### 三. 总结
可以利用KeyAttestation来做什么呢？
1. 验证密钥可信性
密钥认证用于验证设备上的密钥是否由可信的安全硬件生成。通过密钥认证，App可以确保密钥没有被复制或篡改，并且确实是在受信任的环境中创建的
2. 设备身份和完整性验证
密钥认证可以用于验证设备的身份和完整性。通过认证过程中提供的证明数据（比如设备标识符、硬件特性等），可以保证设备没有被篡改或替换

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/keyattestation%E5%8E%9F%E7%90%86%E7%90%86%E8%A7%A3/  


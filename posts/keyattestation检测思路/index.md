# KeyAttestation检测思路


### 思路
怎么可以利用Android提供的KeyAttestation认证方式来做设备异常性的检测呢？首先想想KeyAttestation是什么？能够提供什么？
1. 提供可信环境可以支持存储密钥
设备端可以将密钥保存在KeyStore当中并认为该密钥具有绝对安全性
2. 设备身份和完整性校验
验证密钥可信度的方式就是对整条证书链做校验并最终提取根证书进行校验

因此可以看出，核心是对证书链的校验及对根证书的数据进行校验，证书的内容可以从[官方文档](https://source.android.com/docs/security/features/keystore/attestation?hl=zh-cn#construction)中了解

证书可分为证书本身及证书扩展，其中证书本身的序列包括
![](https://github.com/tcc0lin/picx-images-hosting/raw/master/WX20240831-232747@2x.4uavefedxy.webp)
![](https://github.com/tcc0lin/picx-images-hosting/raw/master/WX20240831-232803@2x.1lbrhrqw1x.webp)
- signatureAlgorithm: 用于签署密钥的算法的 AlgorithmIdentifier：ECDSA 用于 EC 密钥，RSA 用于 RSA 密钥。
- signatureValue: BIT STRING，在 ASN.1 DER 编码的 tbsCertificate 上计算的签名。
- tbsCertificate: TBSCertificate 序列

从文档中包括源码实现中可以了解到，这些证书本身的信息是为了做证书链校验的，除此之外，更核心的是根证书扩展字段的校验
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
其中可以利用来做异常性检测的是
1. attestationVersion：attestation版本，采集该字段可以做机型的离群检测
2. attestationSecurityLevel：该字段包括设备所支持的可信环境版本，同理可以做离群检测
3. keymasterVersion：同上
4. keymasterSecurityLevel：同上
5. teeEnforced-rootOfTrust（通常是在设备制造商在出厂时写入设备）
    - verifiedBootKey：验证设备Bootloader的公钥，可以在后台做机型版本检测
    - deviceLocked：设备解锁状态，可以直接检测
    - verifiedBootState：同上，可以直接检测
    - verifiedBootHash：当前启动链完整性的哈希值，包括Bootloader和所有加载和验证的启动相关分区，可以在后台做机型版本检测

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/keyattestation%E6%A3%80%E6%B5%8B%E6%80%9D%E8%B7%AF/  


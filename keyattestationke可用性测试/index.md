# KeyAttestation原理理解


### 一、Key Attestation密钥认证
根据[官方文档](https://source.android.com/docs/security/features/keystore/attestation?hl=zh-cn#attestation-extension)的阐述
- Keymaster在Android7.0 (Keymaster 2) 中引入了密钥认证
- 在 Android8.0 (Keymaster 3) 中引入了ID认证
### 二、检测方式
有关于KeyAttestation的检测方式目前已有了完成的开源方式---[KeyAttestation](https://github.com/vvb2060/KeyAttestation)

从源码上看看具体的检测思路，首先从入口上看
```xml
# AndroidManifest.xml

<application
      android:name=".AppApplication"
      android:icon="@drawable/ic_launcher"
      android:label="@string/app_name"
      android:roundIcon="@drawable/ic_launcher"
      android:supportsRtl="true"
      android:theme="@style/AppTheme"
      tools:ignore="AllowBackup">
      <activity
          android:name=".home.HomeActivity"
          android:exported="true">
          <intent-filter>
              <action android:name="android.intent.action.MAIN" />
              <category android:name="android.intent.category.LAUNCHER" />
          </intent-filter>
      </activity>

      <provider
          android:name="androidx.startup.InitializationProvider"
          android:authorities="${applicationId}.androidx-startup"
          android:exported="false"
          tools:ignore="MissingClass"
          tools:node="remove" />
      <receiver
          android:name="androidx.profileinstaller.ProfileInstallReceiver"
          android:exported="false"
          tools:ignore="MissingClass"
          tools:node="remove" />
  </application>
```
AppApplication绑定了HomeActivity，对应的Fragment是HomeFragment，ViewModel是HomeViewModel，看看HomeViewModel初始化时做了什么
```java
// io.github.vvb2060.keyattestation.home.HomeViewModel

init {
    load()
}

fun load() = AppApplication.executor.execute {
    currentCerts = null
    attestationResult.postValue(Resource.loading(null))

    val useStrongBox = hasStrongBox && preferStrongBox
    val includeProps = hasDeviceIds && preferIncludeProps
    val useAttestKey = hasAttestKey && preferAttestKey
    val result = try {
        // 核心验证方式
        val attestationResult = doAttestation(useStrongBox, includeProps, useAttestKey)
        Resource.success(attestationResult)
    } catch (e: Throwable) {
        val cause = if (e is AttestationException) e.cause else e
        Log.w(AppApplication.TAG, "Do attestation error.", cause)

        when (e) {
            is AttestationException -> Resource.error(e, null)
            else -> Resource.error(AttestationException(CODE_UNKNOWN, e), null)
        }
    }

    attestationResult.postValue(result)
}
```
深入看看doAttestation函数做了什么
```java
// io.github.vvb2060.keyattestation.home.HomeViewModel

private fun doAttestation(useStrongBox: Boolean,
                          includeProps: Boolean,
                          useAttestKey: Boolean): AttestationResult {
    // useAttestKey通常是false
    val certs: List<Certificate>
    val alias = AppApplication.TAG
    val attestKeyAlias = if (useAttestKey) "${alias}_persistent" else null
    try {
        // 获取AndroidKeyStore实例
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        if (useAttestKey && !keyStore.containsAlias(attestKeyAlias)) {
            generateKey(attestKeyAlias!!, useStrongBox, includeProps, attestKeyAlias)
        }
        // 生成key
        generateKey(alias, useStrongBox, includeProps, attestKeyAlias)
        // 获取密钥别名的列表
        val chainAlias = if (useAttestKey) attestKeyAlias else alias
        // 获取密钥证书链
        val certificates = keyStore.getCertificateChain(chainAlias)
                ?: throw CertificateException("Unable to get certificate chain")
        certs = ArrayList()
        // 获取证书工厂类实例
        val cf = CertificateFactory.getInstance("X.509")
        if (useAttestKey) {
            val certificate = keyStore.getCertificate(alias)
                    ?: throw CertificateException("Unable to get certificate")
            val buf = ByteArrayInputStream(certificate.encoded)
            certs.add(cf.generateCertificate(buf))
        }
        for (i in certificates.indices) {
            val buf = ByteArrayInputStream(certificates[i].encoded)
            // 生成证书类实例
            certs.add(cf.generateCertificate(buf))
        }
    } catch (e: ProviderException) {
        val cause = e.cause
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && e is StrongBoxUnavailableException) {
            throw AttestationException(CODE_STRONGBOX_UNAVAILABLE, e)
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && cause is KeyStoreException) {
            when (cause.numericErrorCode) {
                ERROR_ID_ATTESTATION_FAILURE ->
                    throw AttestationException(CODE_DEVICEIDS_UNAVAILABLE, e)

                ERROR_ATTESTATION_KEYS_UNAVAILABLE -> if (cause.isTransientFailure) {
                    throw AttestationException(CODE_OUT_OF_KEYS_TRANSIENT, e)
                } else {
                    throw AttestationException(CODE_OUT_OF_KEYS, e)
                }

                else -> if (cause.isTransientFailure) {
                    throw AttestationException(CODE_UNAVAILABLE_TRANSIENT, e)
                } else {
                    throw AttestationException(CODE_UNAVAILABLE, e)
                }
            }
        } else if (cause?.message?.contains("device ids") == true) {
            throw AttestationException(CODE_DEVICEIDS_UNAVAILABLE, e)
        } else {
            throw AttestationException(CODE_UNAVAILABLE, e)
        }
    } catch (e: Exception) {
        throw AttestationException(CODE_UNKNOWN, e)
    }
    @Suppress("UNCHECKED_CAST")
    currentCerts = certs as List<X509Certificate>
    // 解析证书链
    return parseCertificateChain(certs)
}
```
parseCertificateChain函数
```java
// io.github.vvb2060.keyattestation.attestation.CertificateInfo

public static AttestationResult parseCertificateChain(List<X509Certificate> certs) {
    if (revocationJson == null) {
        try (var input = AppApplication.app.getResources().openRawResource(R.raw.status)) {
            revocationJson = CertificateRevocationStatus.parseStatus(input);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse certificate revocation status", e);
        }
    }

    var infoList = new ArrayList<CertificateInfo>();

    // 从根证书开始校验，根证书作为上一节点
    var parent = certs.get(certs.size() - 1);
    for (int i = certs.size() - 1; i >= 0; i--) {
        // 获取上一节点的公钥
        var parentKey = parent.getPublicKey();
        var info = new CertificateInfo(certs.get(i));
        infoList.add(info);
        // 证书校验
        info.checkStatus(parentKey);
        if (parent == info.cert) {
            info.checkIssuer();
        } else {
            // parent替换成当前节点，含义是当前节点会利用上一节点的公钥来做验证
            parent = info.cert;
        }
        // 解析证书内容
        if (info.checkAttestation()) {
            break;
        }
    }

    return AttestationResult.form(infoList);
}

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
        if (purposes == null) {
            purposes = attestation.getSoftwareEnforced().getPurposes();
        }
        terminate = purposes == null || !purposes.contains(AuthorizationList.KM_PURPOSE_ATTEST_KEY);
    } catch (CertificateParsingException e) {
        certException = e;
        terminate = false;
        checkProvisioningInfo();
    }
    return terminate;
}

private void checkProvisioningInfo() {
    // If have more data later, move to separate class
    var bytes = cert.getExtensionValue("1.3.6.1.4.1.11129.2.1.30");
    if (bytes == null) return;
    try (var is = new ASN1InputStream(bytes)) {
        var string = (ASN1OctetString) is.readObject();
        var cborBytes = string.getOctets();
        var map = (Map) CborDecoder.decode(cborBytes).get(0);
        for (var key : map.getKeys()) {
            var keyInt = ((Number) key).getValue().intValue();
            if (keyInt == 1) {
                certsIssued = CborUtils.getInt(map, key);
            } else {
                Log.w(AppApplication.TAG, "new provisioning info: "
                        + keyInt + " = " + map.get(key));
            }
        }
    } catch (Exception e) {
        Log.e(AppApplication.TAG, "checkProvisioningInfo", e);
    }
}

// io.github.vvb2060.keyattestation.attestation.AttestationResult

public static AttestationResult form(List<CertificateInfo> certs) {
    var result = new AttestationResult(certs);
    result.status = certs.get(0).getIssuer();
    for (var cert : certs) {
        if (cert.getStatus() != CertificateInfo.CERT_NORMAL) {
            result.status = CertificateInfo.KEY_FAILED;
            break;
        }
    }
    var info = certs.get(certs.size() - 1);
    var attestation = info.getAttestation();
    if (attestation != null) {
        result.showAttestation = attestation;
        result.rootOfTrust = attestation.getRootOfTrust();
        result.sw = attestation.getAttestationSecurityLevel() == KM_SECURITY_LEVEL_SOFTWARE;
    } else {
        throw new AttestationException(CODE_CANT_PARSE_CERT, info.getCertException());
    }
    return result;
}
```
### 三、验证效果测试
已解BL锁的Xiaomi Note11测试效果
![](https://pic.imgdb.cn/item/65757659c458853aef9758f0.jpg)
未解BL锁的Samsung S21+测试效果
![](https://pic.imgdb.cn/item/65757659c458853aef9759ff.jpg)

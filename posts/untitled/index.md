# 

再使用PKCS#5填充至32字节即为末尾添加的数据。服务端通过将客户端发送的verify_data与自身计算的值进行比对，可确保整个握手流程的完整性；使用HMAC校验当前数据可以保证消息没有被中间人篡改。

在这些校验都完成后，服务端给客户端返回ChangeCipherSpec消息，告知客户端接下来发送的数据都将经过协商秘钥进行加密。

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/untitled/  


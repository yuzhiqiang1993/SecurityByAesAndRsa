import utils.AESUtils;
import utils.Base64;
import utils.RSAUtils;

/*
 * RSA和AES结合使用
 *
 * */
public class Main {

    /*关于秘钥的长度自己来决定，这里我是为了演示1024长度的和2048长度的都没问题所以用了两个*/


    /*服务端公私钥 RSA 1024  */
    static String severPubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCIarYvrIMZGHKa8f2E6ubg0//28R1zJ4ArD+XELXYvDrM8UBR42PqJCpjPN3hC91YAnnk2Y9U+X5o/rGxH5ZTZzYy+rkAmZFJa1fK2mWDxPYJoxH+DGHQc+h8t83BMB4pKqVPhcJVF6Ie+qpD5RFUU/e5iEz8ZZFDroVE3ubKaKwIDAQAB";
    static String serverPriKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIhqti+sgxkYcprx/YTq5uDT//bxHXMngCsP5cQtdi8OszxQFHjY+okKmM83eEL3VgCeeTZj1T5fmj+sbEfllNnNjL6uQCZkUlrV8raZYPE9gmjEf4MYdBz6Hy3zcEwHikqpU+FwlUXoh76qkPlEVRT97mITPxlkUOuhUTe5sporAgMBAAECgYA0aSND37iifKUTaKOpXIKFoI23910EMAnrAXmaTIkafUBZjL7Ay0Q+QIcDHeGjgNlW9YvGXMbB5wMhMYKMgOUV1FpeqQdDslO4Z7zynRjkDJkjOKkE2/j10CvmNO8e2uCWKsYYUE9IyTkxcypjBCv16ifT0qmdxb7uKLccYI16eQJBANMutfNO/q7kUKiYvilBLN9+pZOg6eTmKmV0Xygoa3ClpQTfurwLA8W/Fv3oXnjHXTryNVHeoxSH69imo0RZ9kcCQQClXhMbXlfvl5iInmwziFhtYBztvkLuyQ084FgszR7iR0nuOWoURLQa5O7sLL724FNRlSvOCmmmWguh2vmQgRr9AkBDS5tHkWCvMqpRT3spgk9eWOlChgCCpKXV9qNsFJVILEDNsM28pnXpSd91wdp4+m7HHe/Hyv6EyFtrio50dYZ5AkAODVVwUO8GBArJKTUml+JzwOQUa8OCSQFf9+xmOjPypH4qySQzfrcTRfrrhM3haqSJ3TQwuP/LTAGLCnGEjwP9AkBqFFyrrQviPOhwel3NWjRv8mftOFgnm0Isk/NQJ4JtoahYvPDeUyP80WSuVWnPyV4zHz9Kw7BggYCPc4xZDACV";

    /* 客户端公私钥 RSA 2048*/
    static String clientPubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAichGTEP0QFswnvn+ZAQrgGHM8VeDZLJuezGhgxh4d9SyRUfnIW/zefT71rwS4bZUs1MPxJwavOyxABJOHLuckdHXknCsGEWz78gsA6D0+O+9dl1gCZR29nnN/NlzmNbSjFnzvsTJYBlS88qSr35RXFE+6DM7uPsS8Fm2I+65FteJ8p2yMvpSg72QkIX8xvI1F1uwXrciIB+4u7uTozxIplMOo4a6uhAm3W+Kjpz3ni2btjGqHRbqb3ebSZyl+nFfnjQaBe3XyVxAWDSanjgFj/wbqbeug9FBs+nQFVPIZR9z0aE5Ndi5o3eSkV7HFmWpkxaiPZ0BLRK3XHMaBtuSpwIDAQAB";
    static String clientPriKey = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCJyEZMQ/RAWzCe+f5kBCuAYczxV4Nksm57MaGDGHh31LJFR+chb/N59PvWvBLhtlSzUw/EnBq87LEAEk4cu5yR0deScKwYRbPvyCwDoPT47712XWAJlHb2ec382XOY1tKMWfO+xMlgGVLzypKvflFcUT7oMzu4+xLwWbYj7rkW14nynbIy+lKDvZCQhfzG8jUXW7BetyIgH7i7u5OjPEimUw6jhrq6ECbdb4qOnPeeLZu2MaodFupvd5tJnKX6cV+eNBoF7dfJXEBYNJqeOAWP/Bupt66D0UGz6dAVU8hlH3PRoTk12Lmjd5KRXscWZamTFqI9nQEtErdccxoG25KnAgMBAAECggEBAIPz1b88ZTMtIgdejA7lH3Q4Nbn8gc1yRPSet3uBd/3rKT/IeMZBHQBzaqxgOgUIRV3n8nXsun6sf2b+IOjLlErimH2agnZMauL85YokH/g4QU6WZl9GXBf41xmMd3SsZ8AadaEBfYoXNqZcHtcLNogfFwvx5QRnD+A3SoRnH8OLBeVvOEe4AqHLT2xEZ9TeCf3fJe0Rf0fUIbw7I5ioiRZV/ir0L1VM7+1k2JODUkdC2Luj5Tl3nl1Eg6EmkYCmGE1bip1NAatsfjPBLMF7XdPNjLboiffjgKVBOjb7Y9vL18BCoLtWeTT2GkMpi5Sr94T1te1Ox77dF4BP33Xn7eECgYEA1TNUrAQsh14NbbkwFtUHXS8/YXt81p9wbSpFBymIawF2Lkk0913TB4CHSun45LhYXjdZZxK/TgqC5EIq5v2RA0jY3cSxoqVe6RZKB04E8wszeJHiEJPdu2vFnpZh9iAyhswiM5FmuKZKoWsVc2SZrBXAI02smSn3lXYok1VBS3sCgYEApXEZS6gjUu4o7ZL53Ur1HDfi/nxpkxqrPh+D1HVYjzjT+4vTeZwtLXt2VCInPWNXH+f11mzhxIrLkI0jMcSCah81DuU8aFXnqvPuyFvt9uaQBYlVWBtkcGZyeaxHFrbfCyeu0jm7SfwmiIg12hKlIHtPTjEZQUX+kkWr8cdaZ8UCgYEAh0Pl+K09QzVc97yC0jmeTnTnlYWvksvdnKUw3nZvYtSukndH75nLhfr524HOs+5xwnUDd+3hCjaJDSEd7yf5lUfmr+1XdoXNTb0igrfxU/JLWbfU4geuqnaaDyACTxHmfLePC4C413ZJ61fxaCDvjsrN+JgTZanGt0EcRT3WC3kCgYEAgf5/GMJxlw0JXbs515a5R8Xl9358Whj/at3KcRsPTeIiNqnkrc54dR9ol60KViMDZ0+VDDobn5pLXzZ26/jzXD1PLHgU4gp18Q6glhAdx/3cNm11gLhtUCA/XLlwVjm0wggZRpgUQIr/IBKe9c3mr8IUS2Uq6e38nKRf+adhst0CgYAM4tvl+U1MPbbz3YzDv8QPepZ7Pglgdfxqfr5OkXA7jNhqTZjSq10B6oClGvirBo1m6f26F02iUKk1n67AuiLlTP/RRZHi1cfq6P9IaXl23PcxJfUMvIxQDS0U+UTFpNXryTw/qNAkSfufN48YzKdGvc8vHrYJyaeemaVlbdJOCw==";


    public static void main(String[] args) {

        /*单向认证*/
        System.out.println("单向认证流程，服务端给客户端传数据");
        OnewayAuthentication();

        System.out.println("--------------------------------");

        /*双向认证*/
        System.out.println("双向认证流程");

        TwowayAuthentication();

    }


    /**
     * 双向认证
     */
    private static void TwowayAuthentication() {
        /*服务端要传输给客户端的明文数据*/


        try {
            serverToClient();
            System.out.println("-----------------------------------");
            cilentToServer();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /*
     * 服务端给客户端传输数据时
     * */
    private static void serverToClient() throws Exception {

        /*首先模拟服务端给客户端传递数据*/
        System.out.println("服务端给客户端传输数据开始--------");

        String severData = "{'fig':1,'message':'我是服务端返回的数据'}";
        System.out.println("服务端要传输的明文数据：" + severData);
        /*服务端生成的AES随机key*/
        String serverRandomKey = AESUtils.getRandomKey(16);
        System.out.println("服务端生成的随机密码" + serverRandomKey);


        /*1.服务端先将要传输的明文数据用AES加密*/
        String serverAesEncryptData = AESUtils.encrypt(severData, serverRandomKey);
        System.out.println("服务端对明文使用AES加密后：" + serverAesEncryptData);
        /*2.服务端使用服务端的私钥对AES的密码进行加密*/
        byte[] serverEncryptAesAKey = RSAUtils.encryptByPrivateKey(serverRandomKey.getBytes(), serverPriKey);
        System.out.println("AES密码用服务端RSA私钥加密后：" + Base64.encode(serverEncryptAesAKey));

        /*传输数据给客户端*/

        System.out.println("把数据通过接口返回给客户端--------");

        /*3.客户端接收到数据后，先用服务端提供的公钥对加密过的AES密码进行解密*/
        byte[] decryptServerAesKey = RSAUtils.decryptByPublicKey(serverEncryptAesAKey, severPubKey);
        System.out.println("客户端使用服务端提供的RSA公钥解密后AES的KEY：" + new String(decryptServerAesKey));
        /*4.使用解密后的aeskey对加密数据进行解密*/
        String decryptServerData = AESUtils.decrypt(serverAesEncryptData, new String(decryptServerAesKey));
        System.out.println("客户端最终解密的数据：" + decryptServerData);

        System.out.println("客户端接收服务端传输的数据结束--------");

    }

    /*
     * 客户端给服务端传数据
     * */
    private static void cilentToServer() throws Exception {


        System.out.println("客户端给服务端传输的数据开始--------");

        /*要提交的数据*/
        String clientData = "name='yzq'&age=10";
        System.out.println("客户端要提交给服务端的数据：" + clientData);

        /*客户端生成的AES随机key*/
        String clientRandomKey = AESUtils.getRandomKey(16);
        System.out.println("客户端产生的随机密码" + clientRandomKey);
        /*1.客户端先将要传输的明文数据用AES加密*/
        String clientAesEncryptData = AESUtils.encrypt(clientData, clientRandomKey);
        System.out.println("客户端对明文使用AES加密后：" + clientAesEncryptData);
        /*2.客户端使用客户端RSA私钥对AES的密码进行加密*/
        byte[] clientEncryptAesAKey = RSAUtils.encryptByPrivateKey(clientRandomKey.getBytes(), clientPriKey);
        System.out.println("AES密码用客户端RSA私钥加密后：" + Base64.encode(clientEncryptAesAKey));

        /*传输数据给服务端*/
        System.out.println("把数据通过接口提交给服务端--------");

        /*3.服务端接收到数据后，先用客户端提供的公钥对加密过的AES密码进行解密*/
        byte[] decryptClientAesKey = RSAUtils.decryptByPublicKey(clientEncryptAesAKey, clientPubKey);
        System.out.println("服务端使用客户端提供的RSA公钥解密后的AES的KEY：" + new String(decryptClientAesKey));
        /*4.使用解密后的aeskey对加密数据进行解密*/
        String decryptClientData = AESUtils.decrypt(clientAesEncryptData, new String(decryptClientAesKey));
        System.out.println("服务端最终解密的数据：" + decryptClientData);

        System.out.println("服务端接收客户端传输的数据结束--------");


    }


    /**
     * 单向认证，模拟服务端给客户端传输数据
     */
    private static void OnewayAuthentication() {

        /*要传输的明文数据*/
        String data = "{'fig':1,'message':'数据请求成功'}";

        System.out.println("要传输的明文数据：" + data);
        /*AES随机key*/
        String randomKey = AESUtils.getRandomKey(16);

        System.out.println("产生的随机密码" + randomKey);

        /*下面模仿的是客户端给服务端传输数据*/
        try {

            /*1.服务端先将要传输的明文数据用AES加密*/
            String aesEncryptData = AESUtils.encrypt(data, randomKey);
            System.out.println("服务端明文使用AES加密后：" + aesEncryptData);
            /*2.服务端使用私钥对AES的密码进行加密*/
            byte[] encryptAesAKey = RSAUtils.encryptByPrivateKey(randomKey.getBytes(), serverPriKey);
            System.out.println("AES密码用服务端私钥加密后：" + Base64.encode(encryptAesAKey));

            /*传输数据给客户端*/

            /*3.客户端接收到数据后，先用服务端给的公钥对加密过的AES密码进行解密*/
            byte[] decryptAesKey = RSAUtils.decryptByPublicKey(encryptAesAKey, severPubKey);
            System.out.println("客户端用公钥解密后获得AES的KEY：" + new String(decryptAesKey));
            /*客户端使用解密后的aeskey对加密数据进行解密*/
            String decryptData = AESUtils.decrypt(aesEncryptData, new String(decryptAesKey));
            System.out.println("客户端使用解密后的KEY对加密数据进行解密：" + decryptData);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}




import utils.AESUtils;
import utils.Base64;
import utils.RSAUtils;

import java.util.Random;

/*
 * RSA和AES结合使用
 *
 * */
public class Main {

    public static void main(String[] args) {


        /*要传输的明文数据*/
        String data = "{'fig':1,'message':'该设备不允许登录'}";

        /*RSA  1024 */
        String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCIarYvrIMZGHKa8f2E6ubg0//28R1zJ4ArD+XELXYvDrM8UBR42PqJCpjPN3hC91YAnnk2Y9U+X5o/rGxH5ZTZzYy+rkAmZFJa1fK2mWDxPYJoxH+DGHQc+h8t83BMB4pKqVPhcJVF6Ie+qpD5RFUU/e5iEz8ZZFDroVE3ubKaKwIDAQAB";
        String privateKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIhqti+sgxkYcprx/YTq5uDT//bxHXMngCsP5cQtdi8OszxQFHjY+okKmM83eEL3VgCeeTZj1T5fmj+sbEfllNnNjL6uQCZkUlrV8raZYPE9gmjEf4MYdBz6Hy3zcEwHikqpU+FwlUXoh76qkPlEVRT97mITPxlkUOuhUTe5sporAgMBAAECgYA0aSND37iifKUTaKOpXIKFoI23910EMAnrAXmaTIkafUBZjL7Ay0Q+QIcDHeGjgNlW9YvGXMbB5wMhMYKMgOUV1FpeqQdDslO4Z7zynRjkDJkjOKkE2/j10CvmNO8e2uCWKsYYUE9IyTkxcypjBCv16ifT0qmdxb7uKLccYI16eQJBANMutfNO/q7kUKiYvilBLN9+pZOg6eTmKmV0Xygoa3ClpQTfurwLA8W/Fv3oXnjHXTryNVHeoxSH69imo0RZ9kcCQQClXhMbXlfvl5iInmwziFhtYBztvkLuyQ084FgszR7iR0nuOWoURLQa5O7sLL724FNRlSvOCmmmWguh2vmQgRr9AkBDS5tHkWCvMqpRT3spgk9eWOlChgCCpKXV9qNsFJVILEDNsM28pnXpSd91wdp4+m7HHe/Hyv6EyFtrio50dYZ5AkAODVVwUO8GBArJKTUml+JzwOQUa8OCSQFf9+xmOjPypH4qySQzfrcTRfrrhM3haqSJ3TQwuP/LTAGLCnGEjwP9AkBqFFyrrQviPOhwel3NWjRv8mftOFgnm0Isk/NQJ4JtoahYvPDeUyP80WSuVWnPyV4zHz9Kw7BggYCPc4xZDACV";

        /*AES随机key*/
        String randomKey = String.valueOf(new Random().nextInt(999999));

        System.out.println("产生的随机密码" + randomKey);



        /*下面模仿的是服务端给客户端传输数据*/
        try {
            /*1.先将要传输的明文数据用AES加密*/
            byte[] aesEncryptData = AESUtils.aesEncryptToBytes(data, randomKey);
            System.out.println("明文使用aes加密后：" + Base64.encode(aesEncryptData));
            /*2.使用RSA私钥对AES的密码进行加密*/
            byte[] encryptAesAKey = RSAUtils.encryptByPrivateKey(randomKey.getBytes(), privateKey);
            System.out.println("AES密码用RSA加密后：" + Base64.encode(encryptAesAKey));

            /*传输数据*/

            /*3.客户端接收到数据后，先用公钥对加密过的AES密码进行解密*/
            byte[] decryptAesKey = RSAUtils.decryptByPublicKey(encryptAesAKey, publicKey);
            System.out.println("解密后的AES的KEY：" + new String(decryptAesKey));
            /*使用解密后的aeskey对加密数据进行解密*/
            String decryptData = AESUtils.aesDecryptByBytes(aesEncryptData, new String(decryptAesKey));
            System.out.println("最终解密的数据：" + decryptData);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}

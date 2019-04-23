package utils;


import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;


/**
 * @author : yzq
 * @Description: RSA工具类，支持长度为2048的秘钥
 * @date : 2019/3/18
 * @time : 16:29
 */
public class RSAUtils {


    /**
     * 加密算法RSA
     */
    private static final String KEY_ALGORITHM = "RSA";

    /**
     * 签名算法
     */
    // public static final String SIGNATURE_ALGORITHM = "MD5withRSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private static final String cipherMode = "RSA/ECB/PKCS1Padding";

    /**
     * 获取公钥的key
     */
    private static final String PUBLIC_KEY = "RSAPublicKey";


    /**
     * 获取私钥的key
     */
    private static final String PRIVATE_KEY = "RSAPrivateKey";


    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;


    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 256;


    public static void main(String[] args) {


        /*RSA  1024 */
//        String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCIarYvrIMZGHKa8f2E6ubg0//28R1zJ4ArD+XELXYvDrM8UBR42PqJCpjPN3hC91YAnnk2Y9U+X5o/rGxH5ZTZzYy+rkAmZFJa1fK2mWDxPYJoxH+DGHQc+h8t83BMB4pKqVPhcJVF6Ie+qpD5RFUU/e5iEz8ZZFDroVE3ubKaKwIDAQAB";
//        String privateKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIhqti+sgxkYcprx/YTq5uDT//bxHXMngCsP5cQtdi8OszxQFHjY+okKmM83eEL3VgCeeTZj1T5fmj+sbEfllNnNjL6uQCZkUlrV8raZYPE9gmjEf4MYdBz6Hy3zcEwHikqpU+FwlUXoh76qkPlEVRT97mITPxlkUOuhUTe5sporAgMBAAECgYA0aSND37iifKUTaKOpXIKFoI23910EMAnrAXmaTIkafUBZjL7Ay0Q+QIcDHeGjgNlW9YvGXMbB5wMhMYKMgOUV1FpeqQdDslO4Z7zynRjkDJkjOKkE2/j10CvmNO8e2uCWKsYYUE9IyTkxcypjBCv16ifT0qmdxb7uKLccYI16eQJBANMutfNO/q7kUKiYvilBLN9+pZOg6eTmKmV0Xygoa3ClpQTfurwLA8W/Fv3oXnjHXTryNVHeoxSH69imo0RZ9kcCQQClXhMbXlfvl5iInmwziFhtYBztvkLuyQ084FgszR7iR0nuOWoURLQa5O7sLL724FNRlSvOCmmmWguh2vmQgRr9AkBDS5tHkWCvMqpRT3spgk9eWOlChgCCpKXV9qNsFJVILEDNsM28pnXpSd91wdp4+m7HHe/Hyv6EyFtrio50dYZ5AkAODVVwUO8GBArJKTUml+JzwOQUa8OCSQFf9+xmOjPypH4qySQzfrcTRfrrhM3haqSJ3TQwuP/LTAGLCnGEjwP9AkBqFFyrrQviPOhwel3NWjRv8mftOFgnm0Isk/NQJ4JtoahYvPDeUyP80WSuVWnPyV4zHz9Kw7BggYCPc4xZDACV";


        /*RSA 2048*/

        String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAswSYu13+yGlDdAUgAxKcJ81Edt04+CjJUuzqmYmO91ubXCcz7cwy6EHfkk++VuZLAXut/sfQa/jlScTOaUgJos67zWJIrifYc1VQqV3y7pG2HeVOJGAuXBzkPXRDXsIVAYRZRFxU++mI3lo8dvOvORWIO1xMH9TJjBzV0UR888qEXeHd1a80qqTVoKawfiy1nVremtbuJIbu5ZSpruM0RAu2rENg0qr4oHmI2bUq3vECrYYPp+kBbp81dDgQDycOrQPr7JEM1ucJZDz2zU0m2UxboNohjAizteoBkEaKj0503e2AUP09ie7knWoZxtPAzolugpbxT3AO1lgbHKL5pwIDAQAB";
        String privateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCzBJi7Xf7IaUN0BSADEpwnzUR23Tj4KMlS7OqZiY73W5tcJzPtzDLoQd+ST75W5ksBe63+x9Br+OVJxM5pSAmizrvNYkiuJ9hzVVCpXfLukbYd5U4kYC5cHOQ9dENewhUBhFlEXFT76YjeWjx28685FYg7XEwf1MmMHNXRRHzzyoRd4d3VrzSqpNWgprB+LLWdWt6a1u4khu7llKmu4zREC7asQ2DSqvigeYjZtSre8QKthg+n6QFunzV0OBAPJw6tA+vskQzW5wlkPPbNTSbZTFug2iGMCLO16gGQRoqPTnTd7YBQ/T2J7uSdahnG08DOiW6ClvFPcA7WWBscovmnAgMBAAECggEAKzt58w3hIN8i9hrivzs4UPhmh1onju6yp/8lLM0mpKAP5fJlvRDqXmLCLmBptCzLgmEvBO+Wauzh2q3Xt185TIMmoZQRv1VKFZhN8YkJyQmRdKjS9T/xEje7+wdf2bt/PS2MLVErCOc+MYyTO5rf/yYvDz7b93f48IhqLq6einU/l95tbNEc3gXjhSlihuZKr/6KD1++k4AEEBrl5oPa3DBZouhY6HHGCAclNTlzivfvm5WAjdCE3LMlrodC1ACjgGyDZcOIHIPkOcqFLfxIydI0nVEuFPuIWjeyOzGf3EeBjtesiK09SRsK5ddFrDOzby/fpAHWrhiwFmYqv84XgQKBgQDY1e+bZjRCAqbTxzH0uKvVTKvHnNJyc47jh0P02UijVWhrm/d4t9wKH7DYnWBZwZAesYM6XDAzbMYFZ5KLw3EPcIt1fyuMHxeVCz00UH3IEozN8QxWlhrlHik6ik8A9Kqr67Jcs4KeZaumZRWmmX4SRE7jY712O+3QP/AgDAU9wQKBgQDTWgqppLxIiu4MzIzKY5VkhiuvInqX0MJZ0I8kMRvtRh/b34/T+GjT+r1g3AgSHWcwf9nPufwlYWSwoPzGSPhGCF75T2CF4IXEEAnJ4zCJVK7amybgrlAQZXLGXKaIZHr2T6dHQknjJsfYQWKUFde72oxXt/gvjoNK+eCs5GFhZwKBgQC1LBtldkHXnauSa28cEGjScZtdz3Qu2Mrc5RosrJf6kNQMhWaCYOzjMJNsiiIFHKu0WZFR49EKRqo1vdI+IPCIe/qqE7VpAFmN2LQsz8worQck03EBr62NHmRIW2OjYspvlyGSPxK2EjEXeIJcjwc9cAGSELYu4efUBng17pU6gQKBgQCxsKMES27M4pkPA65eveis8iyp+qftGWM81Z5yxCMBkpJYbhXjFZc0mTs8wuC6MiQ+X08FWQ1HdCGOalr6bgDmCEWo/3ZcOA7ebsl8BdkZrKuxOP4vqf3AOzqK0Pxl8Wx7xy4ROAccxc8A3r/9VnvhAPY7DX3Ipd12XKzrTrscgwKBgFCMCYDMMh1ERiImsa5DE4/ndTuI7rILr77JvkfuNbAqTbaF1C9AHYi4WYR/tqwmNRJySjCUuMKavgEdk3V12kz6uQKRqIKb81xClAuYloZufuGGx26wvFPVw6o7ykfbtaaDxdl2Ifplck18+Gu5hETPOdUoIltCGmtA6csNOfkJ";


        try {

            String data = "要传输的数据";

            byte[] publicEncryptBytes = RSAUtils.encryptByPublicKey(data.getBytes(), publicKey);
            System.out.println("公钥加密后的数据：" + Base64.encode(publicEncryptBytes));
            byte[] privatDecryptBytes = RSAUtils.decryptByPrivateKey(publicEncryptBytes, privateKey);
            System.out.println("私钥解密后的数据：" + new String(privatDecryptBytes));


            System.out.println("--------------------");

            byte[] privateKeyEncryptBytes = RSAUtils.encryptByPrivateKey(data.getBytes(), privateKey);
            System.out.println("私钥加密后的数据：" + Base64.encode(privateKeyEncryptBytes));

            String singnData = RSAUtils.sign(data.getBytes(), privateKey);
            System.out.println("私钥签名后的数据：" + singnData);


            byte[] publicDecryptBytes = RSAUtils.decryptByPublicKey(privateKeyEncryptBytes, publicKey);
            System.out.println("公钥解密后的数据：" + new String(publicDecryptBytes));

            boolean isSign = RSAUtils.verify(data.getBytes(), publicKey, singnData);
            System.out.println("签名是否正确：" + isSign);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * @param keySize 生成的秘钥长度  一般为1024或2048
     * @return
     * @throws Exception
     */
    public static Map<String, Object> genKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(keySize);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap<String, Object>(2);
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);

        System.out.println("publicKey：" + Base64.encode(publicKey.getEncoded()));
        System.out.println("privateKey：" + Base64.encode(privateKey.getEncoded()));

        return keyMap;
    }


    /**
     * 对已加密数据进行签名
     *
     * @param data       已加密的数据
     * @param privateKey 私钥
     * @return 对已加密数据生成的签名
     * @throws Exception
     */

    public static String sign(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateK);
        signature.update(data);
        return Base64.encode(signature.sign());
    }


    /**
     * 验签
     *
     * @param data      签名之前的数据
     * @param publicKey 公钥
     * @param sign      签名之后的数据
     * @return 验签是否成功
     * @throws Exception
     */
    public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {
        byte[] keyBytes = Base64.decode(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicK = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(Base64.decode(sign));
    }


    /**
     * 用私钥对数据进行解密
     *
     * @param encryptedData 使用公钥加密过的数据
     * @param privateKey    私钥
     * @return 解密后的数据
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        //Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        Cipher cipher = Cipher.getInstance(cipherMode);
        cipher.init(Cipher.DECRYPT_MODE, privateK);

        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();


        return decryptedData;
    }

    /**
     * 公钥解密
     *
     * @param encryptedData 使用私钥加密过的数据
     * @param publicKey     公钥
     * @return 解密后的数据
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey) throws Exception {
        byte[] keyBytes = Base64.decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(cipherMode);
        cipher.init(Cipher.DECRYPT_MODE, publicK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }


    /**
     * 公钥加密
     *
     * @param data      需要加密的数据
     * @param publicKey 公钥
     * @return 使用公钥加密后的数据
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String publicKey) throws Exception {
        byte[] keyBytes = Base64.decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(cipherMode);
        cipher.init(Cipher.ENCRYPT_MODE, publicK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }


    /**
     * 私钥加密
     *
     * @param data       待加密的数据
     * @param privateKey 私钥
     * @return 使用私钥加密后的数据
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(cipherMode);
        cipher.init(Cipher.ENCRYPT_MODE, privateK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }


    /**
     * 获取私钥
     *
     * @param keyMap 生成的秘钥对
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return Base64.encode(key.getEncoded());
    }


    /**
     * 获取公钥
     *
     * @param keyMap 生成的秘钥对
     * @return
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return Base64.encode(key.getEncoded());
    }


}
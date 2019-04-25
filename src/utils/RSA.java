package utils;


import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;


/**
 * @author : yzq
 * @description: RSA加解密
 * @date : 2019/4/25
 * @time : 15:05
 */

public class RSA {


    //加密方式
    private static final String KEY_RSA = "RSA";
    //公钥
    private static final String KEY_RSA_PUBLICKEY = "RSAPublicKey";
    //私钥
    private static final String KEY_RSA_PRIVATEKEY = "RSAPrivateKey";
    //签名算法
    private final static String KEY_RSA_SIGNATURE = "SHA256withRSA";
    //加密方式，算法，填充方式
    private static final String cipherMode = "RSA/ECB/PKCS1Padding";


    /**
     * 测试方法
     */
    public static void main(String[] args) {
        String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAswSYu13+yGlDdAUgAxKcJ81Edt04+CjJUuzqmYmO91ubXCcz7cwy6EHfkk++VuZLAXut/sfQa/jlScTOaUgJos67zWJIrifYc1VQqV3y7pG2HeVOJGAuXBzkPXRDXsIVAYRZRFxU++mI3lo8dvOvORWIO1xMH9TJjBzV0UR888qEXeHd1a80qqTVoKawfiy1nVremtbuJIbu5ZSpruM0RAu2rENg0qr4oHmI2bUq3vECrYYPp+kBbp81dDgQDycOrQPr7JEM1ucJZDz2zU0m2UxboNohjAizteoBkEaKj0503e2AUP09ie7knWoZxtPAzolugpbxT3AO1lgbHKL5pwIDAQAB";
        String privateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCzBJi7Xf7IaUN0BSADEpwnzUR23Tj4KMlS7OqZiY73W5tcJzPtzDLoQd+ST75W5ksBe63+x9Br+OVJxM5pSAmizrvNYkiuJ9hzVVCpXfLukbYd5U4kYC5cHOQ9dENewhUBhFlEXFT76YjeWjx28685FYg7XEwf1MmMHNXRRHzzyoRd4d3VrzSqpNWgprB+LLWdWt6a1u4khu7llKmu4zREC7asQ2DSqvigeYjZtSre8QKthg+n6QFunzV0OBAPJw6tA+vskQzW5wlkPPbNTSbZTFug2iGMCLO16gGQRoqPTnTd7YBQ/T2J7uSdahnG08DOiW6ClvFPcA7WWBscovmnAgMBAAECggEAKzt58w3hIN8i9hrivzs4UPhmh1onju6yp/8lLM0mpKAP5fJlvRDqXmLCLmBptCzLgmEvBO+Wauzh2q3Xt185TIMmoZQRv1VKFZhN8YkJyQmRdKjS9T/xEje7+wdf2bt/PS2MLVErCOc+MYyTO5rf/yYvDz7b93f48IhqLq6einU/l95tbNEc3gXjhSlihuZKr/6KD1++k4AEEBrl5oPa3DBZouhY6HHGCAclNTlzivfvm5WAjdCE3LMlrodC1ACjgGyDZcOIHIPkOcqFLfxIydI0nVEuFPuIWjeyOzGf3EeBjtesiK09SRsK5ddFrDOzby/fpAHWrhiwFmYqv84XgQKBgQDY1e+bZjRCAqbTxzH0uKvVTKvHnNJyc47jh0P02UijVWhrm/d4t9wKH7DYnWBZwZAesYM6XDAzbMYFZ5KLw3EPcIt1fyuMHxeVCz00UH3IEozN8QxWlhrlHik6ik8A9Kqr67Jcs4KeZaumZRWmmX4SRE7jY712O+3QP/AgDAU9wQKBgQDTWgqppLxIiu4MzIzKY5VkhiuvInqX0MJZ0I8kMRvtRh/b34/T+GjT+r1g3AgSHWcwf9nPufwlYWSwoPzGSPhGCF75T2CF4IXEEAnJ4zCJVK7amybgrlAQZXLGXKaIZHr2T6dHQknjJsfYQWKUFde72oxXt/gvjoNK+eCs5GFhZwKBgQC1LBtldkHXnauSa28cEGjScZtdz3Qu2Mrc5RosrJf6kNQMhWaCYOzjMJNsiiIFHKu0WZFR49EKRqo1vdI+IPCIe/qqE7VpAFmN2LQsz8worQck03EBr62NHmRIW2OjYspvlyGSPxK2EjEXeIJcjwc9cAGSELYu4efUBng17pU6gQKBgQCxsKMES27M4pkPA65eveis8iyp+qftGWM81Z5yxCMBkpJYbhXjFZc0mTs8wuC6MiQ+X08FWQ1HdCGOalr6bgDmCEWo/3ZcOA7ebsl8BdkZrKuxOP4vqf3AOzqK0Pxl8Wx7xy4ROAccxc8A3r/9VnvhAPY7DX3Ipd12XKzrTrscgwKBgFCMCYDMMh1ERiImsa5DE4/ndTuI7rILr77JvkfuNbAqTbaF1C9AHYi4WYR/tqwmNRJySjCUuMKavgEdk3V12kz6uQKRqIKb81xClAuYloZufuGGx26wvFPVw6o7ykfbtaaDxdl2Ifplck18+Gu5hETPOdUoIltCGmtA6csNOfkJ";

        String str = "{'name':喻志强}";

        String testData = "gyTZ2zMe39mq28ukemMgApieS7YpLRRbOPyqLyfB91zxg4o4nViNZREEN+MIlQslH6wJH6gpdaiTB+P0pmslhbHq6kvf0RUBB0E6dRUkmDKmw96ekG8TPdCUGP9JEMXdRJtr/J+2s2wFPO/kmk5sUv6X4vZPjS1awsUfR23mDz0QXhvL4Ji1fuNkPEO2H52EnWxE1QKzTWOZzfrJ2DKJjlxh4hNBh7d2RwwyYNZVe/D7oCjLYDbhLgd639E4cHjOJfJ69iINm88usoEFeUkaNm8HiC2VwfOsJkVelLILFFZu+VKtd4pilmb69an0LkKkbGB1U0hSpzCKv3PzTQ6Mug==";

        // 公钥加密，私钥解密
        String encryptByPublicData = encryptByPublic(str, publicKey);
        System.out.println("公钥加密后：" + encryptByPublicData);
        String decryptByPrivateData = decryptByPrivate(encryptByPublicData, privateKey);
        System.out.println("私钥解密后：" + decryptByPrivateData);
        // 私钥加密，公钥解密
        String encryptByPrivateData = encryptByPrivate(str, privateKey);
        System.out.println("私钥加密后：" + encryptByPrivateData);
        String decryptByPublicData = decryptByPublic(encryptByPrivateData, publicKey);
        System.out.println("公钥解密后：" + decryptByPublicData);
        // 产生签名  
        String signData = sign(encryptByPrivateData, privateKey);
        System.out.println("签名后的数据:" + signData);
        // 验证签名 
        boolean status = verify(encryptByPrivateData, publicKey, signData);
        System.out.println("验签是否成功:" + status);

    }


    /**
     * 生成公私密钥对
     */
    public static Map<String, Object> init() {
        Map<String, Object> map = null;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_RSA);
            //设置密钥对的bit数，越大越安全，但速度减慢，一般使用512或1024
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            // 获取公钥  
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            // 获取私钥  
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            // 将密钥对封装为Map
            map = new HashMap<String, Object>();
            map.put(KEY_RSA_PUBLICKEY, publicKey);
            map.put(KEY_RSA_PRIVATEKEY, privateKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return map;
    }

    /**
     * 获取Base64编码的公钥字符串
     */
    public static String getPublicKey(Map<String, Object> map) {
        String str = "";
        Key key = (Key) map.get(KEY_RSA_PUBLICKEY);
        str = base64Encode2Str(key.getEncoded());
        return str;
    }

    /**
     * 获取Base64编码的私钥字符串
     */
    public static String getPrivateKey(Map<String, Object> map) {
        String str = "";
        Key key = (Key) map.get(KEY_RSA_PRIVATEKEY);
        str = base64Encode2Str(key.getEncoded());
        return str;
    }

    /**
     * BASE64 解码
     *
     * @param data 需要Base64解码的字符串
     * @return 字节数组
     */
    private static byte[] base64Decode2Byte(String data) {


        return Base64.decode(data);
    }

    /**
     * BASE64 编码
     *
     * @param dataBytes 需要Base64编码的字节数组
     * @return 字符串
     */
    private static String base64Encode2Str(byte[] dataBytes) {
        return Base64.encode(dataBytes);
    }


    /**
     * 公钥加密
     *
     * @param data         需要加密的字符串
     * @param publicKeyStr 公钥
     * @return 经过Base64编码后的加密字符串
     */
    public static String encryptByPublic(String data, String publicKeyStr) {
        try {
            // 将公钥由字符串转为UTF-8格式的字节数组
            byte[] publicKeyBytes = base64Decode2Byte(publicKeyStr);
            // 获得公钥  
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            // 将待加密的数据转成字节数组
            byte[] dataBytes = data.getBytes("UTF-8");
            KeyFactory factory;
            factory = KeyFactory.getInstance(KEY_RSA);
            PublicKey publicKey = factory.generatePublic(keySpec);
            // 对数据加密  
            Cipher cipher = Cipher.getInstance(cipherMode);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            // 将加密后的数据用Base64编码成字符串
            return base64Encode2Str(cipher.doFinal(dataBytes));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 私钥解密
     *
     * @param data          需要解密的字符串
     * @param privateKeyStr 私钥
     * @return 经过Base64编码后的解密数据
     */
    public static String decryptByPrivate(String data, String privateKeyStr) {
        try {
            // 对私钥解密  
            byte[] privateKeyBytes = base64Decode2Byte(privateKeyStr);
            // 获得私钥 
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            // 将要解密的字符串转成Base64解码后的字节数组
            byte[] dataBytes = base64Decode2Byte(data);
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            PrivateKey privateKey = factory.generatePrivate(keySpec);
            // 对数据解密
            Cipher cipher = Cipher.getInstance(cipherMode);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            // 返回UTF-8编码的解密信息
            return new String(cipher.doFinal(dataBytes), "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 私钥加密
     *
     * @param data 需要加密的字符串
     * @param privateKeyStr 私钥
     * @return 经过Base64编码后的加密字符串
     */
    public static String encryptByPrivate(String data, String privateKeyStr) {
        try {
            byte[] privateKeyBytes = base64Decode2Byte(privateKeyStr);
            // 获得私钥  
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            // 将待加密的数据转成字节数组
            byte[] dataBytes = data.getBytes("UTF-8");
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            PrivateKey privateKey = factory.generatePrivate(keySpec);
            // 对数据加密 
            Cipher cipher = Cipher.getInstance(cipherMode);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            // 返回加密后由Base64编码的加密信息
            return base64Encode2Str(cipher.doFinal(dataBytes));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 公钥解密
     *
     * @param data
     * @param publicKeyStr
     * @return
     */
    public static String decryptByPublic(String data, String publicKeyStr) {
        try {
            // 对公钥解密  
            byte[] publicKeyBytes = base64Decode2Byte(publicKeyStr);
            // 取得公钥  
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            // 将要解密的字符串转成Base64解码后的字节数组
            byte[] dataBytes = base64Decode2Byte(data);
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            PublicKey publicKey = factory.generatePublic(keySpec);
            // 对数据解密  
            Cipher cipher = Cipher.getInstance(cipherMode);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            // 返回UTF-8编码的解密信息
            return new String(cipher.doFinal(dataBytes), "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 用私钥对加密数据进行签名
     *
     * @param data       需要进行签名的字符串
     * @param privateKeyStr 私钥
     * @return 经过Base64编码后的签名数据
     */
    public static String sign(String data, String privateKeyStr) {
        String str = "";
        try {
            //将私钥加密数据字符串转换为字节数组
            byte[] dataBytes = data.getBytes();
            // 解密由base64编码的私钥  
            byte[] privateKeyBytes = base64Decode2Byte(privateKeyStr);
            // 构造PKCS8EncodedKeySpec对象  
            PKCS8EncodedKeySpec pkcs = new PKCS8EncodedKeySpec(privateKeyBytes);
            // 指定的加密算法  
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            // 取私钥对象  
            PrivateKey key = factory.generatePrivate(pkcs);
            // 用私钥对信息生成数字签名  
            Signature signature = Signature.getInstance(KEY_RSA_SIGNATURE);
            signature.initSign(key);
            signature.update(dataBytes);
            str = base64Encode2Str(signature.sign());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return str;
    }

    /**
     * 校验数字签名
     *
     * @param data 需要进行验签的加密数据
     * @param publicKeyStr    公钥
     * @param sign         原数据
     * @return 校验成功返回true，失败返回false
     */
    public static boolean verify(String data, String publicKeyStr, String sign) {
        boolean flag = false;
        try {
            //将私钥加密数据字符串转换为字节数组
            byte[] dataBytes = data.getBytes();
            // 解密由base64编码的公钥  
            byte[] publicKeyBytes = base64Decode2Byte(publicKeyStr);
            // 构造X509EncodedKeySpec对象  
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            // 指定的加密算法  
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            // 取公钥对象  
            PublicKey key = factory.generatePublic(keySpec);
            // 用公钥验证数字签名  
            Signature signature = Signature.getInstance(KEY_RSA_SIGNATURE);
            signature.initVerify(key);
            signature.update(dataBytes);
            flag = signature.verify(base64Decode2Byte(sign));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return flag;
    }
}
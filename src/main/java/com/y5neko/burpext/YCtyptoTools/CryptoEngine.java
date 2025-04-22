package com.y5neko.burpext.YCtyptoTools;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Hex;

public class CryptoEngine {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String encrypt(String plaintext, Map<String, String> params) throws Exception {
        String algorithm = params.get("algorithm").toUpperCase();
        switch (algorithm) {
            case "AES":
            case "DES":
            case "SM4":
                return encryptSymmetric(plaintext, params);
            case "RSA":
                return encryptRSA(plaintext, params.get("publicKey"));
            case "SM2":
                return encryptSM2(plaintext, params.get("publicKey"));
            case "URL":
                return URLEncoder.encode(plaintext, "UTF-8");
            case "MD5":
                return getMD5Hash(plaintext);
            case "SHA-1":
                return getSHA1Hash(plaintext);
            case "SM3":
                return getSM3Hash(plaintext);
            case "BASE64":
                return Base64.getEncoder().encodeToString(plaintext.getBytes(StandardCharsets.UTF_8));
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }

    public static String decrypt(String ciphertext, Map<String, String> params) throws Exception {
        String algorithm = params.get("algorithm").toUpperCase();
        switch (algorithm) {
            case "AES":
            case "DES":
            case "SM4":
                return decryptSymmetric(ciphertext, params);
            case "RSA":
                return decryptRSA(ciphertext, params.get("privateKey"));
            case "SM2":
                return decryptSM2(ciphertext, params.get("privateKey"));
            case "URL":
                return URLDecoder.decode(ciphertext, "UTF-8");
            case "BASE64":
                return Base64.getEncoder().encodeToString(ciphertext.getBytes(StandardCharsets.UTF_8));
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }

    private static String encryptSymmetric(String plaintext, Map<String, String> params) throws Exception {
        String algorithm = params.get("algorithm").toUpperCase();

        if ("SM4".equals(algorithm)) {
            return encryptSM4(plaintext, params);
        }

        Cipher cipher = getSymmetricCipher(params, Cipher.ENCRYPT_MODE);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static String decryptSymmetric(String ciphertext, Map<String, String> params) throws Exception {
        String algorithm = params.get("algorithm").toUpperCase();

        if ("SM4".equals(algorithm)) {
            return decryptSM4(ciphertext, params);
        }

        Cipher cipher = getSymmetricCipher(params, Cipher.DECRYPT_MODE);
        byte[] decoded = Base64.getDecoder().decode(ciphertext);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private static Cipher getSymmetricCipher(Map<String, String> params, int mode) throws Exception {
        String algorithm = params.get("algorithm");
        String transformation = algorithm + "/" + params.get("mode") + "/" + params.get("padding");

        Cipher cipher = Cipher.getInstance(transformation);

        // 密钥格式解析
        String keyFormat = params.getOrDefault("keyFormat", "utf8");
        byte[] keyBytes = decodeByFormat(params.get("key"), keyFormat);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, algorithm);

        boolean needIV = !"ECB".equalsIgnoreCase(params.get("mode"));
        if (needIV) {
            String ivFormat = params.getOrDefault("ivFormat", "utf8");
            byte[] ivBytes = decodeByFormat(params.get("iv"), ivFormat);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            cipher.init(mode, keySpec, ivSpec);
        } else {
            cipher.init(mode, keySpec);
        }

        return cipher;
    }

    private static byte[] decodeByFormat(String input, String format) {
        switch (format.toLowerCase()) {
            case "base64":
                return Base64.getDecoder().decode(input);
            case "hex":
                return hexStringToByteArray(input);
            case "utf8":
            default:
                return input.getBytes(StandardCharsets.UTF_8);
        }
    }

    private static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        if (len % 2 != 0) throw new IllegalArgumentException("Invalid hex string.");
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        return data;
    }

    private static String encryptRSA(String plaintext, String publicKeyStr) throws Exception {
        PublicKey publicKey = loadPublicKey(publicKeyStr);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static String decryptRSA(String ciphertext, String privateKeyStr) throws Exception {
        PrivateKey privateKey = loadPrivateKey(privateKeyStr);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decoded = Base64.getDecoder().decode(ciphertext);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private static PublicKey loadPublicKey(String base64Key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    private static PrivateKey loadPrivateKey(String base64Key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    private static String getMD5Hash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5算法不存在", e);
        }
    }

    private static String getSHA1Hash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hashBytes = md.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1算法不存在", e);
        }
    }

    private static String getSM3Hash(String input) {
        try {
            SM3Digest digest = new SM3Digest();
            byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
            digest.update(inputBytes, 0, inputBytes.length);

            byte[] hashBytes = new byte[digest.getDigestSize()];
            digest.doFinal(hashBytes, 0);

            return Hex.toHexString(hashBytes);
        } catch (Exception e) {
            throw new RuntimeException("SM3算法处理失败", e);
        }
    }

    private static String encryptSM4(String plaintext, Map<String, String> params) throws Exception {
        String mode = params.getOrDefault("mode", "CBC");
        String padding = params.getOrDefault("padding", "PKCS5Padding");
        String keyFormat = params.getOrDefault("keyFormat", "utf8");
        String ivFormat = params.getOrDefault("ivFormat", "utf8");

        byte[] keyBytes = decodeByFormat(params.get("key"), keyFormat);
        byte[] ivBytes = decodeByFormat(params.get("iv"), ivFormat);

        PaddedBufferedBlockCipher cipher;
        if ("CBC".equalsIgnoreCase(mode)) {
            cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new SM4Engine()));
        } else {
            cipher = new PaddedBufferedBlockCipher(new SM4Engine());
        }

        KeyParameter keyParam = new KeyParameter(keyBytes);
        ParametersWithIV paramsWithIV = new ParametersWithIV(keyParam, ivBytes);
        cipher.init(true, paramsWithIV);

        byte[] input = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] output = new byte[cipher.getOutputSize(input.length)];

        int outputLen = cipher.processBytes(input, 0, input.length, output, 0);
        outputLen += cipher.doFinal(output, outputLen);

        byte[] result = new byte[outputLen];
        System.arraycopy(output, 0, result, 0, outputLen);

        return Base64.getEncoder().encodeToString(result);
    }

    private static String decryptSM4(String ciphertext, Map<String, String> params) throws Exception {
        String mode = params.getOrDefault("mode", "CBC");
        String padding = params.getOrDefault("padding", "PKCS5Padding");
        String keyFormat = params.getOrDefault("keyFormat", "utf8");
        String ivFormat = params.getOrDefault("ivFormat", "utf8");

        byte[] keyBytes = decodeByFormat(params.get("key"), keyFormat);
        byte[] ivBytes = decodeByFormat(params.get("iv"), ivFormat);
        byte[] inputBytes = Base64.getDecoder().decode(ciphertext);

        PaddedBufferedBlockCipher cipher;
        if ("CBC".equalsIgnoreCase(mode)) {
            cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new SM4Engine()));
        } else {
            cipher = new PaddedBufferedBlockCipher(new SM4Engine());
        }

        KeyParameter keyParam = new KeyParameter(keyBytes);
        ParametersWithIV paramsWithIV = new ParametersWithIV(keyParam, ivBytes);
        cipher.init(false, paramsWithIV);

        byte[] output = new byte[cipher.getOutputSize(inputBytes.length)];

        int outputLen = cipher.processBytes(inputBytes, 0, inputBytes.length, output, 0);
        outputLen += cipher.doFinal(output, outputLen);

        byte[] result = new byte[outputLen];
        System.arraycopy(output, 0, result, 0, outputLen);

        return new String(result, StandardCharsets.UTF_8);
    }

    private static String encryptSM2(String plaintext, String publicKeyStr) throws Exception {
        // 加载公钥
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(
                keyFactory.getKeySpec(loadPublicKeySM2(publicKeyBytes), ECPublicKeySpec.class).getQ(),
                keyFactory.getKeySpec(loadPublicKeySM2(publicKeyBytes), ECPublicKeySpec.class).getParams()
        );
        PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);

        // 创建加密器
        Cipher cipher = Cipher.getInstance("SM2", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // 加密数据
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static String decryptSM2(String ciphertext, String privateKeyStr) throws Exception {
        // 加载私钥
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        ECPrivateKeySpec privKeySpec = new ECPrivateKeySpec(
                keyFactory.getKeySpec(loadPrivateKeySM2(privateKeyBytes), ECPrivateKeySpec.class).getD(),
                keyFactory.getKeySpec(loadPrivateKeySM2(privateKeyBytes), ECPrivateKeySpec.class).getParams()
        );
        PrivateKey privateKey = keyFactory.generatePrivate(privKeySpec);

        // 创建解密器
        Cipher cipher = Cipher.getInstance("SM2", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // 解密数据
        byte[] decoded = Base64.getDecoder().decode(ciphertext);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private static PublicKey loadPublicKeySM2(byte[] publicKeyBytes) throws Exception {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        ECPoint point = ecSpec.getCurve().decodePoint(publicKeyBytes);
        return KeyFactory.getInstance("EC", "BC").generatePublic(new ECPublicKeySpec(point, ecSpec));
    }

    private static PrivateKey loadPrivateKeySM2(byte[] privateKeyBytes) throws Exception {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        return KeyFactory.getInstance("EC", "BC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1, privateKeyBytes), ecSpec));
    }

    private static String getApiProcResult(String apiUrl, String data, boolean isDecrypt) throws IOException {
        URL obj = new URL(apiUrl);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();

        // 设置请求方式
        con.setRequestMethod("POST");

        // 启用写入 body
        con.setDoOutput(true);
        try (OutputStream os = con.getOutputStream()) {
            os.write(data.getBytes(StandardCharsets.UTF_8));
        }

        // 读取响应
        int responseCode = con.getResponseCode();
        System.out.println("响应码: " + responseCode);
        try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
            String inputLine;
            StringBuilder response = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            return response.toString();
        }
    }

    public static void main(String[] args) throws Exception {
        // Test SM4
        Map<String, String> sm4Params = new HashMap<>();
        sm4Params.put("algorithm", "SM4");
        sm4Params.put("mode", "CBC");
        sm4Params.put("padding", "PKCS5Padding");
        sm4Params.put("key", "0123456789ABCDEFFEDCBA9876543210");
        sm4Params.put("keyFormat", "hex");
        sm4Params.put("iv", "0123456789ABCDEFFEDCBA9876543210");
        sm4Params.put("ivFormat", "hex");

        String sm4Encrypted = CryptoEngine.encrypt("hello SM4 测试", sm4Params);
        System.out.println("SM4加密后：" + sm4Encrypted);
        System.out.println("SM4解密后：" + CryptoEngine.decrypt(sm4Encrypted, sm4Params));

        // Test SM3
        System.out.println("SM3哈希：" + getSM3Hash("hello SM3 测试"));

        // Note: SM2 testing requires actual key pairs which are too long to include here
    }
}
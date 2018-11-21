
import com.sun.crypto.provider.RSACipher;
import sun.security.rsa.RSAPadding;
import sun.security.rsa.RSAPrivateCrtKeyImpl;
import sun.security.rsa.RSAPrivateKeyImpl;
import sun.security.rsa.RSAPublicKeyImpl;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

/*
 * @URL    : URLDecoder.encrypt/decrypt
 * @Base64 : Base64.getEncoder().encode/Base64.getDecoder().decode <<== java.util  @since JDK8
 * @Base64 : new Base64().encode/decode  <== apache common codec
 * @Base64 : new BASE64Decoder().decodeBuffer/new BASE64Encoder().encodeBuffer
 * @Base54 : BASE64DecoderStream.encode/decode
 * @Hex    : Crypto.Hex.toHexString/toByteArray
 * @MD5    : Crypto.MD5
 * @AES    : Crypto.AES.encrypt/decrypt
 * @RSA    : Crypto.RSA.encrypt/decrypt
 */

public class Crypto {
    public static class Hex {

        private final static char[] hexChar = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
        };

        public static String toHexString(byte[] b) {
            if (b == null) return null;
            if (b.length == 0) return "";

            StringBuilder sb = new StringBuilder(b.length << 1);
            for (byte b1 : b) {
                sb.append(hexChar[(b1 >> 4) & 0x0f]);
                sb.append(hexChar[(b1) & 0x0f]);
            }

            return sb.toString();
        }

        public static byte[] toByteArray(String hex) {
            if (hex == null) return null;
            if (hex.isEmpty()) return new byte[0];
            if ((hex.length() & 1) == 1) throw new RuntimeException();

            byte[] result = new byte[hex.length() >>> 1];

            int k = 0;
            int b1;
            int b = 0;
            for (int i = 0; i < hex.length(); i++) {
                char c = hex.charAt(i);
                if (c >= '0' && c <= '9') b1 = c - '0';
                else if (c >= 'a' && c <= 'f') b1 = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') b1 = c - 'A' + 10;
                else throw new RuntimeException();

                if ((i & 1) == 0) {
                    b = b1;
                } else {
                    result[k++] = (byte) (b << 4 | b1);
                }
            }

            return result;
        }
    }

    public static class MD5 {
        public static String hash(byte[] data) {
            return Hex.toHexString(byteHash(data));
        }

        public static byte[] byteHash(byte[] data) {
            try {
                MessageDigest md5 = MessageDigest.getInstance("MD5");
                md5.update(data);
                return md5.digest();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static class Base64 {
        public static byte[] encode(byte[] data) {
            // @since JDK 1.8
            if (true) return java.util.Base64.getEncoder().encode(data);

            // apache common codec
            return new org.apache.commons.codec.binary.Base64().encode(data);
        }

        public static byte[] decode(byte[] data) {
            // @since JDK 1.8
            if (true) return java.util.Base64.getDecoder().decode(data);

            // apache common codec
            return new org.apache.commons.codec.binary.Base64().decode(data);
        }
    }

    /**
     * AES algorithm
     *
     * @bitlen : 128/192/256
     * @mode : CBC/ECB
     * @paddingType : PKCS5Padding
     */
    public static class AES {
        public final static int BITLEN_128 = 128;
        public final static int BITLEN_192 = 192;
        public final static int BITLEN_256 = 256;
        public final static String CBC = "CBC";
        public final static String ECB = "ECB";
        public final static String PKCS5_PADDING = "PKCS5Padding";

        public static byte[] encrypt(byte[] data, String key, int bitlen, String mode, String paddingType, byte[]... iv) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/" + mode + "/" + paddingType);
            if ("CBC".equals(mode)) {
                byte[] ivb;
                if (iv.length == 0) ivb = new byte[16];
                else ivb = iv[0];
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(genSecretKey(key, bitlen).getEncoded(), "AES"), new IvParameterSpec(ivb));
            } else if ("ECB".equals(mode)) {
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(genSecretKey(key, bitlen).getEncoded(), "AES"));
            } else {
                throw new NoSuchAlgorithmException();
            }
            return cipher.doFinal(data);
        }

        public static byte[] decrypt(byte[] data, String key, int bitlen, String mode, String paddingType, byte[]... iv) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/" + mode + "/" + paddingType);
            if ("CBC".equals(mode)) {
                byte[] ivb;
                if (iv.length == 0) ivb = new byte[16];
                else ivb = iv[0];
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(genSecretKey(key, bitlen).getEncoded(), "AES"), new IvParameterSpec(ivb));
            } else if ("ECB".equals(mode)) {
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(genSecretKey(key, bitlen).getEncoded(), "AES"));
            } else {
                throw new NoSuchAlgorithmException();
            }

            return cipher.doFinal(data);
        }

        private static SecretKey genSecretKey(String key, int bitlen) {
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
                secureRandom.setSeed(key.getBytes(StandardCharsets.UTF_8));
                kgen.init(bitlen, secureRandom);

                return kgen.generateKey();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

    }

    /**
     * RSA algorithm
     *
     * @key private key or public key
     * @mode ECB
     * @paddingType PKCS1Padding/OAEPWithMD5AndMGF1Padding/OAEPWithSHA-256AndMGF1Padding
     */
    public static class RSA {
        public final static String ECB = "ECB";
        public final static String PKCS5_PADDING = "PKCS5Padding";
        public final static String OAEP_WITH_MD5_AND_MGF1_PADDING = "OAEPWithMD5AndMGF1Padding";
        public final static String OAEP_WITH_SHA256_AND_MGF1_PADDING = "OAEPWithSHA-256AndMGF1Padding";

        public static byte[] encrypt(byte[] data, Key key, String mode, String paddingType) {
            try {
                Cipher cipher = Cipher.getInstance("RSA/" + mode + "/" + paddingType);
                cipher.init(Cipher.ENCRYPT_MODE, key);

                int i = 0;
                int inputLen = data.length;
                byte[] buf;
                ByteArrayOutputStream out = new ByteArrayOutputStream();

                int blockSize = getBlockSize(cipher, key, Cipher.ENCRYPT_MODE);
                //System.out.println("blockSize=" + blockSize);

                // 对数据分段加密
                while (i < inputLen) {
                    int len = (inputLen < i + blockSize) ? (inputLen - i) : blockSize;
                    buf = cipher.doFinal(data, i, len);
                    out.write(buf, 0, buf.length);
                    i += blockSize;
                }

                byte[] encryptedData = out.toByteArray();
                out.close();

                return encryptedData;

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public static byte[] decrypt(byte[] data, Key key, String mode, String paddingType) {
            try {
                Cipher cipher = Cipher.getInstance("RSA/" + mode + "/" + paddingType);
                cipher.init(Cipher.DECRYPT_MODE, key);

                int i = 0;
                int inputLen = data.length;
                byte[] buf;
                ByteArrayOutputStream out = new ByteArrayOutputStream();

                int blockSize = getBlockSize(cipher, key, Cipher.DECRYPT_MODE);
                //System.out.println("blockSize=" + blockSize);

                // 对数据分段解密
                while (i < inputLen) {
                    int len = (inputLen < i + blockSize) ? (inputLen - i) : blockSize;
                    buf = cipher.doFinal(data, i, len);
                    out.write(buf, 0, buf.length);
                    i += blockSize;
                }

                byte[] plainData = out.toByteArray();
                out.close();

                return plainData;

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public static byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initSign(privateKey);
            signature.update(data);

            return signature.sign();
        }

        public static boolean verify(byte[] data, PublicKey publicKey, byte[] signatureData) throws Exception {
            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initVerify(publicKey);
            signature.update(data);

            // verify the signature
            return signature.verify(signatureData);
        }

        public static PrivateKey pemToPrivateKey(String privateKeyPem) throws Exception {
            // PKCS#8 format
            final String PEM_PRIVATE_START = "-----BEGIN PRIVATE KEY-----";
            final String PEM_PRIVATE_END = "-----END PRIVATE KEY-----";

            // PKCS#1 format
            final String PEM_RSA_PRIVATE_START = "-----BEGIN RSA PRIVATE KEY-----";
            final String PEM_RSA_PRIVATE_END = "-----END RSA PRIVATE KEY-----";

            if (privateKeyPem.contains(PEM_PRIVATE_START)) { // PKCS#8 format
                privateKeyPem = privateKeyPem.replace(PEM_PRIVATE_START, "").replace(PEM_PRIVATE_END, "");
                privateKeyPem = privateKeyPem.replaceAll("\\s", "");

                byte[] pkcs8EncodedKey = Base64.decode(privateKeyPem.getBytes(StandardCharsets.UTF_8));

                KeyFactory factory = KeyFactory.getInstance("RSA");
                return factory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8EncodedKey));

            } else if (privateKeyPem.contains(PEM_RSA_PRIVATE_START)) {  // PKCS#1 format

                privateKeyPem = privateKeyPem.replace(PEM_RSA_PRIVATE_START, "").replace(PEM_RSA_PRIVATE_END, "");
                privateKeyPem = privateKeyPem.replaceAll("\\s", "");

                DerInputStream derReader = new DerInputStream(Base64.decode(privateKeyPem.getBytes(StandardCharsets.UTF_8)));
                DerValue[] seq = derReader.getSequence(0);

                if (seq.length < 9) {
                    throw new GeneralSecurityException("Could not parse a PKCS1 private key.");
                }

                // skip version seq[0];
                BigInteger modulus = seq[1].getBigInteger();
                BigInteger publicExp = seq[2].getBigInteger();
                BigInteger privateExp = seq[3].getBigInteger();
                BigInteger prime1 = seq[4].getBigInteger();
                BigInteger prime2 = seq[5].getBigInteger();
                BigInteger exp1 = seq[6].getBigInteger();
                BigInteger exp2 = seq[7].getBigInteger();
                BigInteger crtCoef = seq[8].getBigInteger();

                RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);

                KeyFactory factory = KeyFactory.getInstance("RSA");

                return factory.generatePrivate(keySpec);
            }

            throw new GeneralSecurityException("Not supported format of a private key");
        }

        public static PublicKey pemToPublicKey(String publicKeyPem) throws Exception {
            // PKCS#8 format
            final String PEM_PUBLIC_START = "-----BEGIN PUBLIC KEY-----";
            final String PEM_PUBLIC_END = "-----END PUBLIC KEY-----";

            // PKCS#1 format
            final String PEM_RSA_PUBLIC_START = "-----BEGIN RSA PUBLIC KEY-----";
            final String PEM_RSA_PUBLIC_END = "-----END RSA PUBLIC KEY-----";

            if (publicKeyPem.contains(PEM_PUBLIC_START)) { // PKCS#8 format
                publicKeyPem = publicKeyPem.replace(PEM_PUBLIC_START, "")
                    .replace(PEM_PUBLIC_END, "")
                    .replaceAll("\\s", "");

                byte[] x509EncodedKey = Base64.decode(publicKeyPem.getBytes(StandardCharsets.UTF_8));

                KeyFactory factory = KeyFactory.getInstance("RSA");
                return factory.generatePublic(new X509EncodedKeySpec(x509EncodedKey));

            } else if (publicKeyPem.contains(PEM_RSA_PUBLIC_START)) {  // PKCS#1 format

                publicKeyPem = publicKeyPem.replace(PEM_RSA_PUBLIC_START, "")
                    .replace(PEM_RSA_PUBLIC_END, "")
                    .replaceAll("\\s", "");

                DerInputStream derReader = new DerInputStream(Base64.decode(publicKeyPem.getBytes(StandardCharsets.UTF_8)));
                DerValue[] seq = derReader.getSequence(0);

                if (seq.length < 2) {
                    throw new GeneralSecurityException("Could not parse a PKCS1 public key.");
                }

                BigInteger modulus = seq[0].getBigInteger();
                BigInteger publicExponent = seq[1].getBigInteger();

                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);

                KeyFactory factory = KeyFactory.getInstance("RSA");

                return factory.generatePublic(keySpec);
            }

            throw new GeneralSecurityException("Not supported format of a public key");
        }

        private static int getBlockSize(Cipher cipher, Key key, int mode) throws NoSuchAlgorithmException {
            int size;
            if (key instanceof RSAPublicKeyImpl) {
                size = ((RSAPublicKeyImpl) key).getModulus().bitLength();
            } else if (key instanceof RSAPrivateCrtKeyImpl) {
                size = ((RSAPrivateCrtKeyImpl) key).getModulus().bitLength();
            } else if (key instanceof RSAPrivateKeyImpl) {
                size = ((RSAPrivateKeyImpl) key).getModulus().bitLength();
            } else {
                throw new NoSuchAlgorithmException();
            }

            size = size / 8 + 1;
            if (mode == Cipher.DECRYPT_MODE) return size;

            try {
                Field spi = Cipher.class.getDeclaredField("spi");
                spi.setAccessible(true);
                RSACipher rsa = (RSACipher) spi.get(cipher);

                Field padding = RSACipher.class.getDeclaredField("padding");
                padding.setAccessible(true);

                return ((RSAPadding) padding.get(rsa)).getMaxDataSize();
            } catch (Exception e) {
                throw new NoSuchAlgorithmException();
            }
        }
    }
}

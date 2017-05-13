package pe.edu.ulima.app;
import static spark.Spark.*;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class App 
{
    public static void main( String[] args )
    {
    	port(5000);
    
    	options("/*", (request, response) -> {

            String accessControlRequestHeaders = request.headers("Access-Control-Request-Headers");
            if (accessControlRequestHeaders != null) {
                response.header("Access-Control-Allow-Headers", accessControlRequestHeaders);
            }

            String accessControlRequestMethod = request.headers("Access-Control-Request-Method");
            if (accessControlRequestMethod != null) {
                response.header("Access-Control-Allow-Methods", accessControlRequestMethod);
            }

            return "OK";
        });
    	
    	before((request, response) -> {
            response.header("Access-Control-Allow-Origin", "*");
            response.header("Access-Control-Request-Method",  "*");
            response.header("Access-Control-Allow-Headers",  "*");
            // Note: this may or may not be necessary in your particular application
            //response.type("application/html");
        });
    	
    	get("/key", (request, response) -> {
    		SecureRandom random = new SecureRandom();
    		String temp = new BigInteger(130, random).toString(16);
    		SecretKey key = new SecretKeySpec(temp.getBytes()  , "AES");

    		return Base64.getEncoder().encodeToString(key.getEncoded()).substring(0, 16);
    	});
    	
    	post("/encode", (request, response) -> {
    		String texto = request.queryParams("texto");
    		String keyString = request.queryParams("key");
    		
    		Cipher c = Cipher.getInstance("AES/CFB/NoPadding");
            Key key = new SecretKeySpec(keyString.getBytes(), "AES");
            c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[16]));
            
            String rpta = new String (c.doFinal(texto.getBytes()));
            
            return rpta;
    	});
    	
    	post("/decode", (request, response) -> {
    		String texto = request.queryParams("texto");
    		String key = request.queryParams("key");
    		
    		return null;
    	});
    }

    private static byte[] getSaltBytes() throws Exception {
        String salt = "SaltySalt";
    	
    	return salt.getBytes("UTF-8");
    }
}

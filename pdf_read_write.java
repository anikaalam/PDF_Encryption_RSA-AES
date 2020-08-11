import java.math.BigInteger;
import java.security.spec.RSAKeyGenParameterSpec;
import java.net.ServerSocket;
import java.net.Socket;
/* Simple Chat Client */
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.io.InputStream;
import java.io.FilterInputStream;
import java.io.DataInputStream;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.io.FileReader;
import java.net.Socket;
import java.security.*;
import java.security.interfaces.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Base64;
import java.io.InputStream;
import java.io.FileInputStream;
import java.security.Key;
import javax.crypto.KeyGenerator;

import java.util.Base64;
import javax.crypto.*;
import java.security.AlgorithmParameters;
import javax.crypto.Cipher; 
import java.util.*; 
import java.security.spec.*;

import java.security.interfaces.RSAKey;
import java.security.spec.RSAPrivateKeySpec; 
import java.security.spec.RSAPublicKeySpec;

import java.lang.Object;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyStore;
import java.security.KeyFactory;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

public class pdf_read_write {

	public static void main(String[] args) throws Exception{

     

      File file = new File("sample.pdf");
 
        FileInputStream fis = new FileInputStream(file);
        //System.out.println(file.exists() + "!!");
        //InputStream in = resource.openStream();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        
            for (int readNum; (readNum = fis.read(buf)) != -1;) {
                bos.write(buf, 0, readNum); //no doubt here is 0
                //Writes len bytes from the specified byte array starting at offset off to this byte array output stream.
                System.out.println("read " + readNum + " bytes,");
            }
        
        byte[] bytes = bos.toByteArray();
 
        //below is the different part
        File someFile = new File("byteToPDF.pdf");
        FileOutputStream fos = new FileOutputStream(someFile);
        fos.write(bytes);
        fos.flush();
        fos.close();





    
     
	

	}//args check 	

//main 


}//class body 
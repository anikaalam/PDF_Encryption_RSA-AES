
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
import java.io.FileWriter;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import javax.crypto.spec.SecretKeySpec;

public class test_encryption_rsa_aes {

	public static void main(String[] args) throws Exception{

		if(args.length > 1) {
		//String	message;
		//String	returnmessage;
		//String EncodedencryptedStringData; 
		//String EEmessagereturnString;

		//1. read the server's public key 
		File file = new File(args[0]);
        FileInputStream fis = new FileInputStream(file);
        DataInputStream dis = new DataInputStream(fis);

        byte[] keyBytes = new byte[(int) file.length()];
        dis.readFully(keyBytes);
        dis.close();//end of reading the public key

        //1.2. read the server's private key a[1]
		File file2 = new File(args[1]);
        FileInputStream fis3 = new FileInputStream(file2);
        DataInputStream dis3 = new DataInputStream(fis3);

        byte[] keyBytes2 = new byte[(int) file2.length()];
        dis3.readFully(keyBytes2);
        dis3.close();//end of reading the public key
         
        //2. read the pdf file into Byte array 
        //** delete this client reads msg stdin
        //BufferedReader userdata = new BufferedReader(new InputStreamReader(System.in));


        File PDF_file = new File("sample.pdf");
 
        FileInputStream fis2 = new FileInputStream(PDF_file);
        //System.out.println(file.exists() + "!!");
        //InputStream in = resource.openStream();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        
            for (int readNum; (readNum = fis2.read(buf)) != -1;) {
                bos.write(buf, 0, readNum); //no doubt here is 0
                //Writes len bytes from the specified byte array starting at offset off to this byte array output stream.
                System.out.println("read " + readNum + " bytes,");
            }
        
        byte[] bytes_pdf = bos.toByteArray();

        /*
        //3. connect to server
        //server has to be listening on this port
		Socket mysock = new Socket("localhost", 12345); 
		DataOutputStream toServer = new DataOutputStream( mysock.getOutputStream());
		BufferedReader fromServer = new BufferedReader(new InputStreamReader(mysock.getInputStream()));	
		System.out.println("Client is here... " );
        System.out.print("Enter text: ");
        message = userdata.readLine();
        byte[] byteMessage = message.getBytes();
        */
        //Client: plaintext should be read from stdin, but sent to the server after it is encrypted with the Server’s public
		//key and encoded.


        //ENCRYPT TO TEST ENCRYPTION 

        //enc 1. Generate Symmetric Key (AES with 128 bits)
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128); // The AES key size in number of bits
        SecretKey secKey = generator.generateKey();

        //enc 2. Encrypt pdfbyte using the AES symeteric secret key 
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
        byte[] byteCipherText = aesCipher.doFinal(bytes_pdf);

        //enc 3. Encrypt the secret key using RSA public key

        //rebuild RSA public key 
		X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(Base64.getDecoder().decode(keyBytes));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        //RSAPublicKey originalPubKey = (RSAPublicKey)keyFactory.generatePublic(pubSpec);
        PublicKey originalPubKey = keyFactory.generatePublic(pubSpec);

        //Encyrpt with RSA key - encode for safe transmission 
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        //Cipher cipher = Cipher.getInstance("RSA"); // create conversion processing object
   	    cipher.init(Cipher.ENCRYPT_MODE, originalPubKey); // initialize object's mode and key
        byte[] encryptedSecretKeyByte = cipher.doFinal(secKey.getEncoded()); // use object for encryption

        //enc 4. Send encrypted data + encrypted AES Key (encryptedKey) - skip for test purpsoe 


     
        byte[] EncodedencryptedByteData = Base64.getEncoder().encode(byteCipherText);
	

        //enc 5: On the client side, decrypt symmetric key using RSA private key
  

         //ii. reconstruct private key 
         PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(keyBytes2));
         //KeyFactory keyFactory = KeyFactory.getInstance("RSA");
         //RSAPublicKey originalPubKey = (RSAPublicKey)keyFactory.generatePublic(pubSpec);
         PrivateKey originalPrivKey = keyFactory.generatePrivate(privSpec);

         //decode the encoded sewcret key 
         //byte[] DecodeEncrptedSecretKey = Base64.getDecoder().decode(encryptedSecretKeyByte);
         
 
         //iv. decrypt secret using the private  key 
  

        Cipher secret_key_cipher = Cipher.getInstance("RSA"); // create conversion processing object
        secret_key_cipher.init(Cipher.DECRYPT_MODE, originalPrivKey); // initialize object's mode and key
    	byte[] DecryptedByteSecretKey = secret_key_cipher.doFinal(encryptedSecretKeyByte); // use object for encryption

         
      
         //enc 6. Decrypt the pdf_cipher text using decrypted/decoded symmetric key
         //decode the encoded sewcret key 
         byte[] DecodedencryptedByteData = Base64.getDecoder().decode(EncodedencryptedByteData);
         
        //Convert bytes to AES SecertKey
        SecretKey originalKey = new SecretKeySpec(DecryptedByteSecretKey , 0, DecryptedByteSecretKey.length, "AES");
        Cipher aesCipher2 = Cipher.getInstance("AES");
        aesCipher2.init(Cipher.DECRYPT_MODE, originalKey);
        byte[] bytePlainText = aesCipher2.doFinal(DecodedencryptedByteData);
        //String plainText = new String(EncodedencryptedByteData);
        File someFile = new File("byteToPDF_decrypt_test.pdf");
        FileOutputStream fos = new FileOutputStream(someFile);
        fos.write(bytePlainText);
        fos.flush();
        fos.close();











        

        //3. encode pdfByte befor
        // Encode encryptedByteData outputin fnew sample2.pdf
        //byte[] encoded_pdf_bytes = Base64.getEncoder().encode(pdfBytes);

       // FileWriter out;
        //create enplty outfile byte array 
       // String outFile = "";
        //byte[] encoded_pdf_outfile = new byte[(int) pdfBytes.length];
        
     //   out = new FileWriter(encoded_pdf_outfile + "sample2.pdf");
	//	out.write(encoded_pdf_bytes) ;
    //    out.close();
        
      
		

	

	}//args check 	

}//main 
}
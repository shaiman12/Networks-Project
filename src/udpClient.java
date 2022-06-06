import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Scanner;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
 import java.security.InvalidAlgorithmParameterException;
 import java.security.NoSuchAlgorithmException;
 import org.bouncycastle.openpgp.PGPException;
 import org.bouncycastle.openpgp.PGPPublicKeyRing;
 import org.bouncycastle.openpgp.PGPSecretKeyRing;
 import org.pgpainless.key.protection.*;
 import org.bouncycastle.util.io.Streams;
 import org.pgpainless.PGPainless;
 import org.pgpainless.algorithm.HashAlgorithm;
 import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
 import org.pgpainless.encryption_signing.EncryptionOptions;
 import org.pgpainless.encryption_signing.EncryptionStream;
 import org.pgpainless.encryption_signing.ProducerOptions;
 import org.pgpainless.encryption_signing.SigningOptions;
 import org.pgpainless.key.generation.type.rsa.RsaLength;
 import org.pgpainless.algorithm.DocumentSignatureType;
 import org.pgpainless.key.info.KeyRingInfo;

/**
*udpClient
*This class is the platform through which the client interacts with the server and by extension, other clients.
*A udpClient contains a sender and a receiver thread which allow clients to send and receive messages simultaneously. 
*@author FSHJAR002 RSNJOS005
*@since 2021-03-29 
*/

public class udpClient {

  private  DatagramSocket socket;
  private  InetAddress serverAddress;
  private  int port;

  private static PGPSecretKeyRing secretKey = null;
  private static SecretKeyRingProtector protectorKey = null;
  private static PGPPublicKeyRing publicKey = null;

  private static final String privKeyBAD = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
  "Version: PGPainless\n" +
  "Comment: A0D2 F316 0F6B 2CE5 7A50  FF32 261E 5081 9736 C493\n" +
  "Comment: bob@pgpainless.org\n" +
  "\n" +
  "lFgEYksu1hYJKwYBBAHaRw8BAQdAXTBT1OKN1GAvGC+fzuy/k34BK+d5Saa87Glb\n" +
  "iQgIxg8AAPwMI5DGqADFfl6H3Nxj3NxEZLasiFDpwEszluLVRy0jihGbtBJib2JA\n" +
  "cGdwYWlubGVzcy5vcmeIjwQTFgoAQQUCYksu1gkQJh5QgZc2xJMWIQSg0vMWD2ss\n" +
  "5XpQ/zImHlCBlzbEkwKeAQKbAQUWAgMBAAQLCQgHBRUKCQgLApkBAADvrAD/cWBW\n" +
  "mRkSfoCbEl22s59FXE7NPENrsJK8jxmWsWX3jbEA/AyXMCjwH6IhDgdgO7wH2z1r\n" +
  "cUb/hokiCcCaJs6hjKcInF0EYksu1hIKKwYBBAGXVQEFAQEHQCeURSBi9brhisUH\n" +
  "Dz0xN1NCgU5yeirx53xrQDFFx+d6AwEIBwAA/1GHX9+4Rg0ePsXGm1QIWL+C4rdf\n" +
  "AReCTYoS3EBiZVdADoyIdQQYFgoAHQUCYksu1gKeAQKbDAUWAgMBAAQLCQgHBRUK\n" +
  "CQgLAAoJECYeUIGXNsST8c0A/1dEIO9gsFB15UWDlTzN3S0TXQNN8wVzIMdW7XP2\n" +
  "7c6bAQCB5ChqQA9AB1020DLr28BAbSjI7mPdIWg2PpE7B1EXC5xYBGJLLtYWCSsG\n" +
  "AQQB2kcPAQEHQKP5NxT0ZhmRbrl3S6uwrUN248g1TEUR0DCVuLgyGSLpAAEA6bMa\n" +
  "GaUf3S55rkFDjFC4Cv72zc8E5ex2RKgbpxXxqhYQN4jVBBgWCgB9BQJiSy7WAp4B\n" +
  "ApsCBRYCAwEABAsJCAcFFQoJCAtfIAQZFgoABgUCYksu1gAKCRDJLjPCA2NIfylD\n" +
  "AP4tNFV23FBlrC57iesHVc+TTfNJ8rd+U7mbJvUgykcSNAEAy64tKPuVj+aA1bpm\n" +
  "gHxfqdEJCOko8UhVVP6ltiDUcAoACgkQJh5QgZc2xJP9TQEA1DNgFno3di+xGDEN\n" +
  "pwe9lmz8d/RWy/kuBT9S/3CMJjQBAKNBhHPuFfvk7RFbsmMrHsSqDFqIuUfGqq39\n" +
  "VzmiMp8N\n" +
  "=LpkJ\n" +
  "-----END PGP PRIVATE KEY BLOCK-----\n";
  

  
  /**
   * This is the constructor for the udpClient. The relevant attributes to this class are set here.
   * If anything goes wrong with the creating of the socket or threads, the error is caught and printed to terminal.
   * @param destinationAddr The address of the server to send data to.
   * @param port The port of the server to send data to.
   */

  public udpClient(String destinationAddr, int port,  boolean debug) { //Create a new udpClient for a particular user.
    //The address and port of the server are also needed.
    try {
      this.port = port;
      serverAddress = InetAddress.getByName(destinationAddr);
      Scanner input = new Scanner(System.in);
      String uname = (input.nextLine()).trim();
 
      secretKey = PGPainless.generateKeyRing().simpleRsaKeyRing(uname, RsaLength._4096);    //secret key
      protectorKey = SecretKeyRingProtector.unprotectedKeys();
      publicKey = PGPainless.extractCertificate(secretKey); 
      
      socket = new DatagramSocket();
      senderThread sendT = new senderThread(socket, serverAddress, port,secretKey, protectorKey, publicKey, uname, debug);
      receiverThread recieveT = new receiverThread(socket,secretKey, protectorKey, debug);
     // senderThread.sendMessage("connect-User@" + uName); //Call sendMessage() with a message telling the server a new user is connecting.
      new Thread(sendT).start(); //Start a sender thread bound to the udpClient
      new Thread(recieveT).start(); //Start a receiver thread bound to the udpClient
    } catch (Exception e) {
      System.out.println(e);
    }
  }



    

 
}

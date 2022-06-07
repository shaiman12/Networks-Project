import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Scanner;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.protection.SecretKeyRingProtector;

/**
*udpClient
*This class is the platform through which the client interacts with the server and by extension, other clients.
*A udpClient contains a sender and a receiver thread which allow clients to send and receive messages simultaneously. 
*@author FSHJAR002 RSNJOS005 ARNSHA011 SNDJEM002
*@since 2022-05-10
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
   * @param debug Whether or not the user has requested the debug mode to be on.
   */

  public udpClient(String destinationAddr, int port,  boolean debug) { 
    try {
      this.port = port;
      serverAddress = InetAddress.getByName(destinationAddr);
      System.out.println("Please enter your username below:");

      Scanner input = new Scanner(System.in);
      String uname = (input.nextLine()).trim();
 
      secretKey = PGPainless.generateKeyRing().simpleRsaKeyRing(uname, RsaLength._4096);    //secret key
      protectorKey = SecretKeyRingProtector.unprotectedKeys();
      publicKey = PGPainless.extractCertificate(secretKey); 
      
      socket = new DatagramSocket();
      senderThread sendT = new senderThread(socket, serverAddress, port,secretKey, protectorKey, publicKey, uname);
      receiverThread recieveT = new receiverThread(socket,secretKey, protectorKey, debug);
    
      new Thread(sendT).start(); //Start a sender thread bound to the udpClient
      new Thread(recieveT).start(); //Start a receiver thread bound to the udpClient
    } catch (Exception e) {
      System.out.println(e);
    }
  }



    

 
}

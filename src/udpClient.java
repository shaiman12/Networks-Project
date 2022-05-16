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
  

  
  /**
   * This is the constructor for the udpClient. The relevant attributes to this class are set here.
   * If anything goes wrong with the creating of the socket or threads, the error is caught and printed to terminal.
   * @param destinationAddr The address of the server to send data to.
   * @param port The port of the server to send data to.
   */

  public udpClient(String destinationAddr, int port) { //Create a new udpClient for a particular user.
    //The address and port of the server are also needed.
    try {
      this.port = port;
      serverAddress = InetAddress.getByName(destinationAddr);
      Scanner input = new Scanner(System.in);
      String uname = (input.nextLine()).trim();
    //  input.close();
      

      secretKey = PGPainless.generateKeyRing().simpleRsaKeyRing(uname, RsaLength._4096);    //secret key
      protectorKey = SecretKeyRingProtector.unprotectedKeys();
      publicKey = PGPainless.extractCertificate(secretKey); 

      socket = new DatagramSocket();
      senderThread sendT = new senderThread(socket, serverAddress, port,secretKey, protectorKey, publicKey, uname);
      receiverThread recieveT = new receiverThread(socket,secretKey, protectorKey, publicKey);
     // senderThread.sendMessage("connect-User@" + uName); //Call sendMessage() with a message telling the server a new user is connecting.
      new Thread(sendT).start(); //Start a sender thread bound to the udpClient
      new Thread(recieveT).start(); //Start a receiver thread bound to the udpClient
    } catch (Exception e) {
      System.out.println(e);
    }
  }

 
}

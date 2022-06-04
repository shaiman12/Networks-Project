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
import org.pgpainless.util.Passphrase;
import java.nio.charset.Charset;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import java.util.Hashtable;

import java.util.*;

/**
 * senderThread
 * This class implements runnable.
 * The class' primary function is to send user input (as a message)
 * to the server which in turn will distribute these messages to relevant
 * receiver threads.
 * A sender thread is run when a udpClient object is created in a 1:1
 * relationship.
 * Within this class is where user input is requested and processed.
 * To check the integrity of the message being sent, the message’s corresponding
 * hash code is calculated
 * and is appended onto the original message delimited by “@@”.
 * Integrity is then checked when the message arrives at the server.
 * 
 * @author FSHJAR002 RSNJOS005
 * @since 2021-03-31
 */

public class senderThread implements Runnable {


 


  private static DatagramSocket dSock;
  private static InetAddress serverAddress;
  private static int port;
  private static PGPSecretKeyRing secretKey = null;
  private static SecretKeyRingProtector protectorKey = null;
  private static PGPPublicKeyRing publicKey = null;
  private static String uname;
  

  public static boolean isConnected;
  public static Hashtable<String, PGPPublicKeyRing> clientToPubKeyHashTable;

  /**
   * This is the constructor for the senderThread
   * 
   * @param ds       UDP Socket object. Same as the one created in the udpClient
   *                 object.
   * @param sAddress Server address to send data to.
   * @param p        Server's port number to sen secretKey =
   *                 PGPainless.generateKeyRing().simpleRsaKeyRing(uname,
   *                 RsaLength._4096); //secret key
   *                 protectorKey = SecretKeyRingProtector.unprotectedKeys();
   *                 publicKey = PGPainless.extractCertificate(secretKey); d data
   *                 to.
   */
  public senderThread(DatagramSocket ds, InetAddress sAddress, int p, PGPSecretKeyRing sK, SecretKeyRingProtector sP,
      PGPPublicKeyRing pK, String u) { // Create a new sender thread that is bound to the relevant Datagram socket.
    // As well as the server details to which messages must be directed.
    dSock = ds;
    serverAddress = sAddress;
    port = p;
    isConnected = false; // isConnected is set to false until the server has confirmed the user can
                         // connect.
    clientToPubKeyHashTable = new Hashtable<String, PGPPublicKeyRing>();
    uname = u;
    secretKey = sK;
    protectorKey = sP;
    publicKey = pK;
  }

  /**
   * Sender thread starts running. It acts independently of the receiver thread.
   * The run method continously loops through taking in userinput and sending the
   * message on
   * until the user closes their client.
   */
  @Override
  public void run() {

    Scanner input = new Scanner(System.in); // Create a new Scanner for taking in user input.

    String msg = uname;

  
    sendMessage("connect-User@" + msg + "#" + armourPublicKey(publicKey));
    // System.out.println("Username is: " + msg);

    while (true) {
      // block input until at least 2 clients on

      msg = (input.nextLine()).trim();

      // Get the message to be sent from user input.

      if (isConnected) { // If Stringthe user has been allowed into the server.

        try {
          sendEncryptedMessage(msg);

        } catch (Exception e) {
          // TODO: handle exception
        }
      }
      if (msg.contains("@exit@"))
        System.exit(0); // If the user requests to shut their client down then the application is
                        // closed.
      // System.out.println("DONE printing keys");
      // new Thread(new realiableThread(dSock)).start();
    }

  }
  // input.close();

  private static void sendEncryptedMessage(String msg) throws PGPException, IOException {
    ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
    // Encrypt and sign
    EncryptionStream encryptor = PGPainless.encryptAndOrSign()
        .onOutputStream(ciphertext)
        .withOptions(ProducerOptions.signAndEncrypt(
            // we want to encrypt communication (affects key selection based on key flags)
            EncryptionOptions.encryptCommunications()
                .addRecipients(clientToPubKeyHashTable.values())
                .overrideEncryptionAlgorithm(SymmetricKeyAlgorithm.AES_256),
            new SigningOptions()
                .addInlineSignature(protectorKey, secretKey, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT)
                .overrideHashAlgorithm(
                    HashAlgorithm.SHA256))

            .setAsciiArmor(true));

    // Pipe data trough and CLOSE the stream (important)
    Streams.pipeAll(new ByteArrayInputStream(msg.getBytes(StandardCharsets.UTF_8)), encryptor);
    encryptor.close();
    String encryptedMessage = ciphertext.toString();
    sendMessage(encryptedMessage);

  }

  /**
   * Sendmessage function is where the actual sending of the data occurs.
   * This is done through first making a packet which contains the data and the
   * destination address.
   * Then the data is sent with the DatagramSocket.send() function.
   * The message being sent has a hashcode appended onto it for checking integrity
   * at the receiving end.
   * 
   * @param msg The message to be sent.
   */

  public static void sendMessage(String msg) { // This is a simple sendmessage method to send to server.
    // msg = buildMessageChecksum(msg); //Add checksum to message
    byte[] buf = msg.getBytes(); // buffer built from the message.

    DatagramPacket packet = new DatagramPacket( // Create a packet of The buffer, buffer length as well as the IP and
                                                // port of the server.
        buf,
        buf.length,
        serverAddress,
        port);

    try {
      dSock.send(packet); // Try send the message.
    } catch (IOException e) {
      System.out.println(e);
    }
  }

  public static String armourPublicKey(PGPPublicKeyRing keys) {

    // try {
    // ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
    // // Encrypt
    // EncryptionStream encryptor;
    // try {
    // encryptor = PGPainless.encryptAndOrSign()
    // .onOutputStream(ciphertext)
    // .withOptions(ProducerOptions
    // .encrypt(EncryptionOptions.encryptCommunications()
    // .addPassphrase(Passphrase.fromPassword("p4ssphr4s3")))
    // .setAsciiArmor(true));
    // ByteArrayOutputStream baosPkr = new ByteArrayOutputStream();

    // ArmoredOutputStream armoredStreamPkr = new ArmoredOutputStream(baosPkr);
    // keys.encode(armoredStreamPkr);
    // armoredStreamPkr.close();

    // Streams.pipeAll(
    // new ByteArrayInputStream(
    // (new String(baosPkr.toByteArray(),
    // Charset.defaultCharset())).getBytes(StandardCharsets.UTF_8)),
    // encryptor);
    // encryptor.close();

    // String asciiCiphertext = ciphertext.toString();

    // sendMessage(asciiCiphertext);
    // } catch (PGPException e) {
    // // TODO Auto-generated catch block
    // e.printStackTrace();
    // }

    // } catch (IOException e) {
    // // TODO Auto-generated catch block
    // e.printStackTrace();
    // }
    String msgTemp = "";
      try {
        ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
        // Encrypt
        EncryptionStream encryptor = PGPainless.encryptAndOrSign()
                .onOutputStream(ciphertext)
                .withOptions(ProducerOptions
                        .encrypt(EncryptionOptions.encryptCommunications()
                                .addPassphrase(Passphrase.fromPassword("p4ssphr4s3"))
                        ).setAsciiArmor(true)
                );
    
        Streams.pipeAll(new ByteArrayInputStream((PGPainless.asciiArmor(keys)).getBytes(StandardCharsets.UTF_8)), encryptor);
        encryptor.close();
    
        msgTemp = ciphertext.toString();
       
        //sendMessage(asciiCiphertext);
      } catch (Exception e) {
        //TODO: handle exception
      }
      return msgTemp;

    // try {
    //   String asciiArmoredPublicKey = PGPainless.asciiArmor(keys);

    //   sendMessage(asciiArmoredPublicKey);
    // } catch (IOException e) {
    //   // TODO Auto-generated catch block
    //   e.printStackTrace();
    // }

  }

  /**
   * Simple method to create a basic checksum for integrity checking purposes.
   * The hashcode generated is appended to the original message and then checked
   * at the receiving end.
   * 
   * @param msg The message to be sent.
   * @return The message being sent plus the generated hashcode delimmited by
   *         '@@'.
   */

  public static String buildMessageChecksum(String msg) {
    String hash = String.valueOf(msg.hashCode()); // Generate a hashcode of the message to be sent.

    msg += "@@" + hash; // Append the hashcode onto the message. Delimtted by the '@@'.

    return msg;
  }
}

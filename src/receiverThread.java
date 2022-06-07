import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.ArmorUtils;

/**
 * receiverThread This class implements runnable. This class' primary function
 * is to receive messages distributed by the server and print them to screen.
 * All subsequent functionality halts (within the class) while waiting to
 * receive a message and continues after it has. A receiver thread is run when a
 * udpClient object is created in a 1:1 relationship. 
 * 
 * @author FSHJAR002 RSNJOS005 ARNSHA011 SNDJEM002
 * @since 2022-05-11
 */

public class receiverThread implements Runnable {

  private static final String caPubKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
      "Version: PGPainless\n" +
      "Comment: 12E3 4F04 C66D 2B70 D16C  960D ACF2 16F0 F93D DD20\n" +
      "Comment: alice@pgpainless.org\n" +
      "\n" +
      "mDMEYksu1hYJKwYBBAHaRw8BAQdAIhUpRrs6zFTBI1pK40jCkzY/DQ/t4fUgNtlS\n" +
      "mXOt1cK0FGFsaWNlQHBncGFpbmxlc3Mub3JniI8EExYKAEEFAmJLLtYJEKzyFvD5\n" +
      "Pd0gFiEEEuNPBMZtK3DRbJYNrPIW8Pk93SACngECmwEFFgIDAQAECwkIBwUVCgkI\n" +
      "CwKZAQAA45MBAN9SxFBICzR382bhgiur6BTuA51Mm5/fd/+7+7WcYzV8AP9Fjsje\n" +
      "BChnSVZu9dWREAsK71xQl28vuSlbWhi1iDbVC7g4BGJLLtYSCisGAQQBl1UBBQEB\n" +
      "B0DrQXziToxj9TIEJl7j9Y/wkPD8R+7n8bKTyFx3cfMcWwMBCAeIdQQYFgoAHQUC\n" +
      "Yksu1gKeAQKbDAUWAgMBAAQLCQgHBRUKCQgLAAoJEKzyFvD5Pd0gnegA/2Nyxdkb\n" +
      "4GxGjgbQLx+sNGQT6Kwd65OncfgHtBr1uBPMAPkB5oDaNKXZA8U5dATdSguwVdYk\n" +
      "RanvVaO31tiy34ZRBLgzBGJLLtYWCSsGAQQB2kcPAQEHQD7amqdtf85lc8Th5Pvv\n" +
      "PdfxGUjYpMFpKvbdKZmI4bSfiNUEGBYKAH0FAmJLLtYCngECmwIFFgIDAQAECwkI\n" +
      "BwUVCgkIC18gBBkWCgAGBQJiSy7WAAoJEOEz2Vo79YylzN0A/iZAVklSJsfQslsh\n" +
      "R6/zMBufwCK1S05jg/5Ydaksv3QcAQC4gsxdFFne+H4Mmos4atad6hMhlqr0/Zyc\n" +
      "71ZdO5I/CAAKCRCs8hbw+T3dIGhqAQCIdVtCus336cDeNug+E9v1PEM3F/dt6GAq\n" +
      "SG8LJqdAGgEA8cUXdUBooOo/QBkDnpteke8Z3IhIGyGedc8OwJyVFwc=\n" +
      "=GUhm\n" +
      "-----END PGP PUBLIC KEY BLOCK-----\n";

  private DatagramSocket dSock;
  private static PGPSecretKeyRing secretKey = null;
  private static SecretKeyRingProtector protectorKey = null;

  private static Boolean debugOn;

  private static PGPPublicKeyRing certificateAuthorityPublicKey;

  /**
   * Constructor for receiverThread. Sets the DatagramSocket without specifying a
   * particular IP address and port. Also initiliases the CA's public key
   * 
   * @param ds UDP Socket object. Same as the one created in the udpClient object.
   * @param sK The client's private key
   * @param sP The client's private key ring protector
   * @param debug Whether or not the user has requested the debug mode to be on.
   */

  public receiverThread(DatagramSocket ds, PGPSecretKeyRing sK, SecretKeyRingProtector sP, boolean debug) {
    
    dSock = ds;
    secretKey = sK;
    protectorKey = sP;

    debugOn = debug;

    try {
      certificateAuthorityPublicKey = PGPainless.readKeyRing().publicKeyRing(caPubKey);
    } catch (Exception e) {
      
      System.out.println(e);
    }
  }

  /**
   * Receiver thread starts running. It acts independently of the sender thread.
   * The run method continously loops through waiting to receive and print out
   * messages being sent until the user closes their client.
   */
  @Override
  public void run() { // receiver thread starts running. It acts independently of the send thread.
    while (true) {
      byte[] buf = new byte[4096]; // Create buffer with size 1024 bytes.

      DatagramPacket dpRecv = new DatagramPacket(buf, buf.length); // Create new Datagram packet for receiving data.

      try {
        dSock.receive(dpRecv); // Wait to receive the data.
      } catch (IOException e) {
        System.out.println(e);
      }

      String str = new String(dpRecv.getData(), 0, dpRecv.getLength()).trim(); // Get the message sent with the packet.
   
 
      //When the server needs to update all connected client's certificate storage,
      //The server will send a message that contains the "KEYUPDATE@" control message.
      //This is triggered when a new client logs on. The message contains the new client's certificate.
      
      if (str.contains("KEYUPDATE@")) {
        
        try {
          int x = str.indexOf("@");
         
          str = str.substring(x + 1, str.length()).trim();

          ByteArrayInputStream signedIn = new ByteArrayInputStream(str.getBytes(StandardCharsets.UTF_8));

          // and pass it to the decryption stream
          DecryptionStream verificationStream = PGPainless.decryptAndOrVerify()
              .onInputStream(signedIn)
              .withOptions(new ConsumerOptions().addVerificationCert(certificateAuthorityPublicKey));

          // plain will receive the plaintext message

          ByteArrayOutputStream plain = new ByteArrayOutputStream();
          Streams.pipeAll(verificationStream, plain);

          verificationStream.close();

          OpenPgpMetadata metadata = verificationStream.getResult();

          //We check to see that the new certificate for some client is indeed a certificate
          //created by the trusted CA.
          //This is achieved by checking that the message contains a verified signature from the trusted CA.
          

          if (metadata.containsVerifiedSignatureFrom(certificateAuthorityPublicKey)) {

            //Following code is string handling of the message to access the public key stored in the
            //certificate

            int posBegin = str.indexOf("-----BEGIN PGP PUBLIC KEY BLOCK-----");
            int posEnd = str.indexOf("-----END PGP PUBLIC KEY BLOCK-----");

            String pubKeyString = str.substring(posBegin, posEnd - 2) + "-----END PGP PUBLIC KEY BLOCK-----";

            //Extract public key
            PGPPublicKeyRing newClientPubKey = PGPainless.readKeyRing().publicKeyRing(pubKeyString);
            KeyRingInfo keyInfo = new KeyRingInfo(newClientPubKey);
            
            //Extract username from the key information
            String uName = keyInfo.getPrimaryUserId();

            //Add the Username <-> Certificate pairing to the HashTable used by the senderThread

            senderThread.clientToPubKeyHashTable.put(uName, newClientPubKey);

          }

          else 
           //If message does not contain a verified signature from the trusted CA, alert the user.

            System.out.println("Error, certificate not signed by trusted CA. Untrustworthy");

        } catch (Exception e) {
          
          System.out.println(e);
        }
        continue;
      }

      if (str.contains("connected@")) {   //Server notifying client that it has successfully logged in
        senderThread.isConnected = true;
        int x = str.indexOf("@");

        String username = str.substring(x + 1, str.length());
        printWelcomeInformation(username);
        continue;
      }

      if (str.contains("@shutdown@ by user:")) {
        System.out.println( // If any client shuts the server down, all clients are notified.
            "Server has been shutdown, closing Client.");
        System.exit(0);
      }

      if (str.contains(") has entered the chat")) {     //Message letting client know of new client
        System.out.println(str);
        continue;
      }

      if (str.contains("Current users in chat:")) {     //Message letting client know of which clients are in the chat room
        System.out.println(str);
        continue;
      }



      //If user trys to login with username linked to another client already in the chat room,
      //The user will be kicked out and asked to try again

      if (str.contains("The username you entered is linked to a client already logged in. Please restart client and enter valid username.")) {
        System.out.println(str);
        System.exit(0);

      }


      //If user trys to login with username not on the server whitelist,
      //The user will be kicked out and asked to try again

      if (str.contains("You are not on the server whitelist. Please restart client and enter valid username.")) {
        System.out.println(str);
        System.exit(0);

      }


      //Message letting client know of client has just exited the chat room

      if (str.contains("] has disconnected.")) {
        System.out.println(str);
        continue;
      }

      // we decrypt here
      else {

        int pos = str.indexOf("]");
        String uName = str.substring(1, pos);

        String encryptedString = (str.substring(pos + 1, str.length())).trim();

        try {
          System.out.println("[" + uName + "] " + decryptMessage(encryptedString, uName));
        } catch (Exception e) {
          
          System.out.println(e);
        }
      }

      
    }
  }

  /**
   * Decrypt message takes in an encrypted message and decrypts the message using the receiver's
   * private key. This method also verifies that the message was sent by the authorised sender and
   * not a malicious third party. The appropriate certificate used for verification 
   * is accessed from the client's HashTable of Usernames <-> Certificates.
   * In the event that the message is received and is not successfully verified, the user will be 
   * explicitly notified of this authentication issue. Similarly, if the message was sent unencrypted, the user will
   * be notified that confidentiality may have been breached.
   * 
   * If debug mode is on, lots of metadata about the decryption stream will also be printed.
   * 
   * @param str The message to decrypt
   * @param uname The username linked to the client
   * @throws PGPException, IOException
   * @return The decrypted Message
   */

  protected String decryptMessage(String str, String uname) throws PGPException, IOException {


    //Create decryption stream with appropriate options, verificiate certificates
    //and decryption keys

    DecryptionStream decryptor = PGPainless.decryptAndOrVerify()
        .onInputStream(new ByteArrayInputStream(str.getBytes(StandardCharsets.UTF_8)))
        .withOptions(new ConsumerOptions()
            .addDecryptionKey(secretKey, protectorKey)
            
            .addVerificationCert(senderThread.clientToPubKeyHashTable.get(uname)));

    ByteArrayOutputStream plaintext = new ByteArrayOutputStream();

    Streams.pipeAll(decryptor, plaintext);
    decryptor.close();
    OpenPgpMetadata metadata = decryptor.getResult();

    if (debugOn) {
      System.out.println("Encrypted: " + metadata.isEncrypted());
      System.out.println("Session key: " + metadata.getSessionKey().toString());
      System.out.println("Session key Algorithm: " + metadata.getSymmetricKeyAlgorithm().toString());
      System.out.println("Compression Algorithm: " + metadata.getCompressionAlgorithm().toString());

      //Check that the message contains a verified signed by the real, trusted sender.

      System.out.println("Contains verified signature from " + uname
          + " : " + metadata.containsVerifiedSignatureFrom(senderThread.clientToPubKeyHashTable.get(uname)));

      //Print out the signatures from the message (contains the hash of the message)

      for (PGPSignature cig : metadata.getSignatures()) {
        System.out.println(ArmorUtils.toAsciiArmoredString(cig.getEncoded()));
       
      }
    }
 
    //If the message was not signed by the real, trusted sender.
    if (!(metadata.containsVerifiedSignatureFrom(senderThread.clientToPubKeyHashTable.get(uname))))
      System.out.println("WARNING: Message verification failed. Message was not signed by " + uname);

    //If the message was sent unencrypted

    if (!(metadata.isEncrypted()))
      System.out.println("WARNING: Message was not encrypted in transit. Confidentiality lost");

    return plaintext.toString();
  }

  /**
   * This method prints welcome information for the client.
   * It also displays the useful commands available to the user.
   * 
   * @param uname The username linked to the client
   */

  protected void printWelcomeInformation(String uname) {
    System.out.println("\n");
    System.out.println("Welcome to the PGP encrypted NIS chat room, " + uname);
    System.out.println();
    System.out.println("All messages sent between you and other recipients are fully encrypted");
    System.out.println("Messages are also verified by a trusted certificate authority to ensure authenticity");
    System.out.println();
    System.out.println("In addition to sending plain messages, the following commands are available:");
    System.out.println("@shutdown@ \t" + "Shuts the server down.");
    System.out.println("@exit@ \t \t" + "Exits your client.");
    System.out.println("To use these commands, just type them into your console as indicated.");
      System.out.println();
    System.out.print("Connecting ");
    try {
      Thread.sleep(1000);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      System.out.println(e);
    }
    System.out.print(".");
    try {
      Thread.sleep(1000);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      System.out.println(e);
    }
    System.out.print(".");
    try {
      Thread.sleep(1000);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      System.out.println(e);
    }
    System.out.print(".");
    System.out.print("\t Successfully connected.");
    System.out.println();
    System.out.println("You may start typing in the chat now:");
  }

}

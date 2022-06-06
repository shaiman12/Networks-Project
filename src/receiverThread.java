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
import org.bouncycastle.openpgp.PGPSignature;
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
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;

import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.util.ArmorUtils;

/**
 * receiverThread This class implements runnable. This class' primary function
 * is to receive messages distributed by the server and print them to screen.
 * All subsequent functionality halts (within the class) while waiting to
 * receive a message and continues after it has. A receiver thread is run when a
 * udpClient object is created in a 1:1 relationship. The receiverThread class
 * also checks if a message was corrupted between the server and the receiver.
 * It does this by calculating a hash code of the message, then comparing it to
 * the original hash code sent along with the message (see buildChecksum in
 * senderThread). If these hash codes match, then the message arrived
 * uncorrupted.
 * 
 * @author FSHJAR002 RSNJOS005
 * @since 2021-03-31
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
   * particular IP address and port.
   * 
   * @param ds UDP Socket object. Same as the one created in the udpClient object.
   */

  public receiverThread(DatagramSocket ds, PGPSecretKeyRing sK, SecretKeyRingProtector sP, boolean debug) { // Create
                                                                                                            // a
                                                                                                            // new
                                                                                                            // receiver
                                                                                                            // thread
                                                                                                            // bound
                                                                                                            // to
                                                                                                            // the
                                                                                                            // relevant
                                                                                                            // Datagram
                                                                                                            // Socket
                                                                                                            // -
    // this comes from the associated client.
    dSock = ds;
    secretKey = sK;
    protectorKey = sP;

    debugOn = debug;

    try {
      certificateAuthorityPublicKey = PGPainless.readKeyRing().publicKeyRing(caPubKey);
    } catch (Exception e) {
      // TODO: handle exception
      System.out.println("biiiiigg ERROR");
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
      // This currently includes the appended hashcode.

      int y = 0;
      // int iHash = 0; //changed
      String msg = str;
      String errorMsg = "Message corrupted here at receiver side. Please resend Message.";

      if (str.contains("KEYUPDATE@")) {
        // addd all public keys to public key data structure
        try {
          int x = str.indexOf("@");
          // Hash username to key
          msg = msg.substring(x + 1, msg.length()).trim();

          ByteArrayInputStream signedIn = new ByteArrayInputStream(msg.getBytes(StandardCharsets.UTF_8));

          // and pass it to the decryption stream
          DecryptionStream verificationStream = PGPainless.decryptAndOrVerify()
              .onInputStream(signedIn)
              .withOptions(new ConsumerOptions().addVerificationCert(certificateAuthorityPublicKey));

          // plain will receive the plaintext message

          ByteArrayOutputStream plain = new ByteArrayOutputStream();
          Streams.pipeAll(verificationStream, plain);

          verificationStream.close(); // as always, remember to close the stream

          OpenPgpMetadata metadata = verificationStream.getResult();

          if (metadata.containsVerifiedSignatureFrom(certificateAuthorityPublicKey)) {

            int posBegin = msg.indexOf("-----BEGIN PGP PUBLIC KEY BLOCK-----");
            int posEnd = msg.indexOf("-----END PGP PUBLIC KEY BLOCK-----");

            String pubKeyString = msg.substring(posBegin, posEnd - 2) + "-----END PGP PUBLIC KEY BLOCK-----";

            PGPPublicKeyRing newClientPubKey = PGPainless.readKeyRing().publicKeyRing(pubKeyString);
            KeyRingInfo keyInfo = new KeyRingInfo(newClientPubKey);
            String uName = keyInfo.getPrimaryUserId();

            senderThread.clientToPubKeyHashTable.put(uName, newClientPubKey);

          }

          else
            System.out.println("error, certificate not signed by trusted CA");

        } catch (Exception e) {
          // TODO: handle exception
          System.out.println(e);
        }
        continue;
      }

      if (str.contains("connected@")) {
        senderThread.isConnected = true;
        int x = str.indexOf("@");

        String username = str.substring(x + 1, str.length()); // changed
        printWelcomeInformation(username);
        continue;
      }

      if (str.contains("@shutdown@ by user:")) {
        System.out.println( // If any client shuts the server down, all clients are notified.
            "Server has been shutdown, closing Client.");
        System.exit(0);
      }

      if (str.contains(") has entered the chat")) {
        System.out.println(str);
        continue;
      }

      if (str.contains("Current users in chat:")) {
        System.out.println(str);
        continue;
      }

      if (str.contains(
          "The username you entered is linked to a client already logged in. Please restart client and enter valid username.")) {
        System.out.println(str);
        System.exit(0);

      }

      if (str.contains("You are not on the server whitelist. Please restart client and enter valid username.")) {
        System.out.println(str);
        System.exit(0);

      }

      if (str.contains("] has disconnected.")) {
        System.out.println(str);
        continue;
      }

      // we decrypt here
      else {

        int pos = msg.indexOf("]");
        String uName = msg.substring(1, pos);

        String encryptedString = (msg.substring(pos + 1, msg.length())).trim();

        try {
          System.out.println("[" + uName + "] " + decryptMessage(encryptedString, uName));
        } catch (Exception e) {
          // TODO: handle exception
          System.out.println(e);
        }
      }

      // Otherwise, the relevant error message is printed.
    }
  }

  private static String decryptMessage(String msg, String uname) throws PGPException, IOException {

    DecryptionStream decryptor = PGPainless.decryptAndOrVerify()
        .onInputStream(new ByteArrayInputStream(msg.getBytes(StandardCharsets.UTF_8)))
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

      System.out.println("Contains verified signature from " + uname
          + " : " + metadata.containsVerifiedSignatureFrom(senderThread.clientToPubKeyHashTable.get(uname)));

      for (PGPSignature cig : metadata.getSignatures()) {
        System.out.println(ArmorUtils.toAsciiArmoredString(cig.getEncoded()));
       
      }
    }
 
    if (!(metadata.containsVerifiedSignatureFrom(senderThread.clientToPubKeyHashTable.get(uname))))
      System.out.println("WARNING: Message verification failed. Message was not signed by " + uname);

    if (!(metadata.isEncrypted()))
      System.out.println("WARNING: Message was not encrypted in transit. Confidentiality lost");

    return plaintext.toString();
  }

  /**
   * This method prints welcoming messages and information to the client. It is
   * primarily
   * for aesthetic purposes.
   * 
   * @param uname The username linked to the client
   */

  private void printWelcomeInformation(String uname) {
    System.out.println("\n");
    System.out.println("Welcome to the server, " + uname);
    System.out.println();
    System.out.println("The following commands are available to you:");
    System.out.println("@shutdown@ \t" + "Shuts the server down.");
    System.out.println("@exit@ \t \t" + "Closes your client down.");
    System.out.println("@history@ \t" + "Prints the chat history stored on the server.");
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
    System.out.print("\t Connected");
    System.out.println();
    System.out.println("You may begin by typing below:");
  }

  protected static void setPrivKey(PGPSecretKeyRing pS) {
    secretKey = pS;
  }

}

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Hashtable;
import java.util.Scanner;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;

/**
 * senderThread
 * This class implements runnable.
 * The class is responsible for sending user input to the server. 
 * Depending on what is required, messages can also be encrypted. 
 * A sender thread is run when a udpClient object is created in a 1:1
 * relationship.
 * Within this class is where user input is requested and processed.
 * To verify the message came from this trusted client, messages are verified
 * by signing the message with the client's private key. Message integrity can also then
 * be checked on the receiving side as the hash of the message is generated and signed. The receiver
 * will check that the signed message digest matches their own hashing of the decrypted message.
 * 
 * @author FSHJAR002 RSNJOS005 ARNSHA011 SNDJEM002
 * @since 2022-05-11
 */

public class senderThread implements Runnable {


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

  private static DatagramSocket dSock;
  private static InetAddress serverAddress;
  private static int port;
  private static PGPSecretKeyRing secretKey = null;
  private static SecretKeyRingProtector protectorKey = null;
  private static PGPPublicKeyRing publicKey = null;
  private static String uname;

  public static boolean isConnected;

  public static Hashtable<String, PGPPublicKeyRing> clientToPubKeyHashTable;
  private static PGPPublicKeyRing certificateAuthorityPublicKey;

  /**
   * This is the constructor for the senderThread
   * 
   * @param ds       UDP Socket object. Same as the one created in the udpClient
   *                 object.
   * @param sAddress Server address to send data to.
   * @param p        Server's port number
   * @param sK       The client's private key
   * @param sP       The client's private key ring protector
   */
  public senderThread(DatagramSocket ds, InetAddress sAddress, int p, PGPSecretKeyRing sK, SecretKeyRingProtector sP,
      PGPPublicKeyRing pK, String u) { 


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

    
    try {
      certificateAuthorityPublicKey = PGPainless.readKeyRing().publicKeyRing(caPubKey);
    } catch (Exception e) {
      
      System.out.println(e);
    }

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

    sendMessage("connect-User@" + msg + "#" + encryptPublicKey(publicKey));
  
    while (true) {
     
      msg = (input.nextLine()).trim();

    

      if (isConnected) { // If the user has been allowed into the server.

        try {
          if (msg.equals("@exit@") || msg.equals("@shutdown@"))
            sendMessage(msg);

          else

            sendEncryptedMessage(msg);

        } catch (Exception e) {
          System.out.println(e);
        }
      }
      if (msg.contains("@exit@"))
        System.exit(0); // If the user requests to shut their client down then the application is
                        // closed.
  
    }

   

  }

  
  /**
   * sendEncryptedMessage takes in a plaintext message and encrypts the message with an AES_256 symmetric key.
   * This symmetric key is then encrypted with all the currently logged in clients' public keys
   * This method also signs the message with the sender's private key. The signature is in-line
   * and it signs the message digest of the plaintext. The hashing algorithm to produce the message digest
   * is SHA_256.
   * Once the plaintext has been converted into ciphertext,
   * it is then passed to the generic sendMessage function for forwarding to the server.
   * 
   * @param msg The message to encrypt and sign 
   * @throws PGPException, IOException
   */

  protected void sendEncryptedMessage(String msg) throws PGPException, IOException {
    ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
    // Encrypt and sign
    EncryptionStream encryptor = PGPainless.encryptAndOrSign()
        .onOutputStream(ciphertext)
        .withOptions(ProducerOptions.signAndEncrypt(
            

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
   * Sendmessage function is where the messages to be sent are actually passed to the server.
   * This is done through first making a packet which contains the data and the
   * destination address and port.
   * Then the data is sent with the DatagramSocket.send() function.
   * 
   * @param msg The message to be sent.
   */

  protected void sendMessage(String msg) {

    byte[] buf = msg.getBytes(); // buffer built from the message.

    DatagramPacket packet = new DatagramPacket(
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

  /**
   * encryptPublicKey takes in the client's public key and encrypts it with the CA's public key.
   * This is done so that when the client sends its public key over to the CA for signing, a 
   * malicious third party would not be able to intercept this and modify the public key in transit.
   * 
   * @param pubKey The client's public key, unencrypted
   * @return The encrypted public key
   */

  protected String encryptPublicKey(PGPPublicKeyRing pubKey) {

    String msgTemp = "";
    try {
      ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
      // Encrypt
      EncryptionStream encryptor = PGPainless.encryptAndOrSign()
          .onOutputStream(ciphertext)
          .withOptions(ProducerOptions
              .encrypt(EncryptionOptions.encryptCommunications()
                  .addRecipient(certificateAuthorityPublicKey))   //recipient is the CA
              .setAsciiArmor(true));


      //pipe message into encryption stream
      Streams.pipeAll(new ByteArrayInputStream((PGPainless.asciiArmor(pubKey)).getBytes(StandardCharsets.UTF_8)),
          encryptor);
      encryptor.close();

      msgTemp = ciphertext.toString();

    } catch (Exception e) {
      System.out.println(e);
    }
    return msgTemp;

  }

}

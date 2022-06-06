import java.io.*;
import java.lang.Math;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.sound.sampled.SourceDataLine;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.info.KeyRingInfo;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.util.Passphrase;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.key.protection.*;

/**
 * udpServer is the server that udpClients communicate with and through. Since
 * this is the case, it also checks message integrity by comparing hash codes,
 * in the same way that the receiver thread class does. This is to ensure
 * message integrity when the sender communicates with the server. The server
 * broadcasts all messages that it is sent to the clients connected to the
 * server, except to the same client who sent the message. This creates the
 * group chat feature. To allow for this functionality, the server keeps track
 * of all currently connected users though the use of clientObjs – note, this is
 * different to the udpClient class.
 * 
 * @author FSHJAR002 RSNJOS005
 * @since 2021-03-29
 */

public class udpServer extends Thread {

  private static final SecretKeyRingProtector keyProtector = SecretKeyRingProtector.unprotectedKeys();

  private static final String CA_privKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
      "Version: PGPainless\n" +
      "Comment: 12E3 4F04 C66D 2B70 D16C  960D ACF2 16F0 F93D DD20\n" +
      "Comment: alice@pgpainless.org\n" +
      "\n" +
      "lFgEYksu1hYJKwYBBAHaRw8BAQdAIhUpRrs6zFTBI1pK40jCkzY/DQ/t4fUgNtlS\n" +
      "mXOt1cIAAP4wM0LQD/Wj9w6/QujM/erj/TodDZzmp2ZwblrvDQri0RJ/tBRhbGlj\n" +
      "ZUBwZ3BhaW5sZXNzLm9yZ4iPBBMWCgBBBQJiSy7WCRCs8hbw+T3dIBYhBBLjTwTG\n" +
      "bStw0WyWDazyFvD5Pd0gAp4BApsBBRYCAwEABAsJCAcFFQoJCAsCmQEAAOOTAQDf\n" +
      "UsRQSAs0d/Nm4YIrq+gU7gOdTJuf33f/u/u1nGM1fAD/RY7I3gQoZ0lWbvXVkRAL\n" +
      "Cu9cUJdvL7kpW1oYtYg21QucXQRiSy7WEgorBgEEAZdVAQUBAQdA60F84k6MY/Uy\n" +
      "BCZe4/WP8JDw/Efu5/Gyk8hcd3HzHFsDAQgHAAD/aC8DOOkK0XNVz2hkSVczmNoJ\n" +
      "Umog0PfQLRujpOTqonAQKIh1BBgWCgAdBQJiSy7WAp4BApsMBRYCAwEABAsJCAcF\n" +
      "FQoJCAsACgkQrPIW8Pk93SCd6AD/Y3LF2RvgbEaOBtAvH6w0ZBPorB3rk6dx+Ae0\n" +
      "GvW4E8wA+QHmgNo0pdkDxTl0BN1KC7BV1iRFqe9Vo7fW2LLfhlEEnFgEYksu1hYJ\n" +
      "KwYBBAHaRw8BAQdAPtqap21/zmVzxOHk++891/EZSNikwWkq9t0pmYjhtJ8AAP9N\n" +
      "m/G6nbiEB8mu/TkNnb7vdhSmLddL9kdKh0LzWD95LBF0iNUEGBYKAH0FAmJLLtYC\n" +
      "ngECmwIFFgIDAQAECwkIBwUVCgkIC18gBBkWCgAGBQJiSy7WAAoJEOEz2Vo79Yyl\n" +
      "zN0A/iZAVklSJsfQslshR6/zMBufwCK1S05jg/5Ydaksv3QcAQC4gsxdFFne+H4M\n" +
      "mos4atad6hMhlqr0/Zyc71ZdO5I/CAAKCRCs8hbw+T3dIGhqAQCIdVtCus336cDe\n" +
      "Nug+E9v1PEM3F/dt6GAqSG8LJqdAGgEA8cUXdUBooOo/QBkDnpteke8Z3IhIGyGe\n" +
      "dc8OwJyVFwc=\n" +
      "=ARAi\n" +
      "-----END PGP PRIVATE KEY BLOCK-----\n";

  private static final String CA_privKeyBAD = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
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

  private DatagramSocket socket;
  private boolean running;
  private InetAddress addressServer;
  private byte[] buf;
  private int serverPort;
  private ArrayList<clientObj> clientArrayList;
  private ArrayList<String> allowedUsers;
  private Scanner fileIn;
  private PGPPublicKeyRing publicKey;

  private static PGPSecretKeyRing certificateAuthorityPrivateKey;

  private FileWriter chatFileOut;
  private Date currentDate;
  private final SimpleDateFormat FORMATTER = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");

  /**
   * Construction of a udpServer thread requires an IP address and a port number
   * The server is bound to these attributes and it can be either local or WAN.
   * 
   * @param aServer    The address of the server
   * @param port       The port of the server
   *
   */

  public udpServer(String aServer, int port) { // create a new server that is bound to a partiuclar
                                                                   // IP address and port
    serverPort = port;
    running = true;
    clientArrayList = new ArrayList<clientObj>(); // List of client objects
    allowedUsers = new ArrayList<String>(); // List of users allowed to connect
    try {
      fileIn = new Scanner(new FileReader("whitelist.txt")); // The list of users who are allowed to connect
    } catch (FileNotFoundException e) {
      System.out.println("File not found error: " + e);
    }

    while (fileIn.hasNextLine()) {
      allowedUsers.add(fileIn.nextLine().trim()); // Add the allowed users to the list
    }
    fileIn.close();
   
    try {
      addressServer = InetAddress.getByName(aServer);
      socket = new DatagramSocket(serverPort, addressServer); // create a new socket for the server.
    } catch (IOException e) {
      System.out.println(e);
    }

    try {
      certificateAuthorityPrivateKey = PGPainless.readKeyRing().secretKeyRing(CA_privKey);
 
    } catch (Exception e) {
      // TODO: handle exception
      System.out.print(e + "server error");

    }

  }

  /**
   * Server thread starts running. Within this run() method is where all the
   * processing of incoming and outcoming packets takes place.
   * 
   */
  @Override
  public void run() { // server thread starts running.
    boolean terminating = false;
    try {
      System.out.println("-- Running Server at " + InetAddress.getLocalHost() + "--"); // Print the address of where the
                                                                                       // server is running.
    } catch (IOException e) {
      System.out.println(e);
    }

    while (running) { // Loops until running is no longer true. This can happen if the server is
                      // forced or asked to be shutdown.
      buf = new byte[4096]; // Create buffer with size 1024 bytes.

      DatagramPacket packet = new DatagramPacket(buf, buf.length);

      try {
        socket.receive(packet); // Server trys to receive a packet on the socket created for the server.
      } catch (IOException e) {
        System.out.println(e);
      }

      InetAddress address = packet.getAddress(); // Address of where the message has come from is saved.

      int port = packet.getPort(); // Port of where the message has come from is saved.

      String currentUser = returnClientUserName(address, port); // Name of the user from which the message was sent is
                                                                // saved.

      String received = new String(packet.getData(), 0, packet.getLength()).trim(); // Get the buffer that was sent with
                                                                                    // the packet -

      String msg = received;
   

      System.out.println("Message from " + currentUser + "@" + packet.getAddress().getHostAddress() + ": " + msg);
  
      // add public key development here

      if (received.contains("connect-User@")) { // If the user is connecting for the first time and trying to add
                                                // their username.
        int posAt = received.indexOf("@");
        int posHash = received.indexOf("#");
    
        String username = received.substring(posAt + 1, posHash);

        try {
          String asciiCiphertext = received.substring(posHash + 1, received.length());
          DecryptionStream decryptor = PGPainless.decryptAndOrVerify()
              .onInputStream(new ByteArrayInputStream(asciiCiphertext.getBytes(StandardCharsets.UTF_8)))
              .withOptions(new ConsumerOptions().addDecryptionPassphrase(Passphrase.fromPassword("p4ssphr4s3")));

          ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
          Streams.pipeAll(decryptor, plaintext);

          decryptor.close();


          publicKey = PGPainless.readKeyRing().publicKeyRing(plaintext.toString());
          System.out.println(plaintext.toString());
        } catch (Exception e) {
          // TODO: handle exception
        }

        boolean userAlreadyInChat = false;

        for (int i = 0; i < clientArrayList.size(); i++) {
        
          if(clientArrayList.get(i).getUsername().equals(username)){

            sendMessage("The username you entered is linked to a client already logged in. Please restart client and enter valid username.", address, port);
            userAlreadyInChat = true;
            break;
          }

        }

        if(userAlreadyInChat) continue;



        if (allowedUsers.contains(username)) {
          
          // Update new client's public key list with everyother client's public key
          manageClientBase(username, address, port); // Call the manageClientBase method to create a new client object

          for (int i = 0; i < clientArrayList.size(); i++) {
            msg = "KEYUPDATE@";

            msg += clientArrayList.get(i).getCertificate();
            sendMessage(msg, address, port);

          }

          // Update all connected client's with new client's public key

          msg = "KEYUPDATE@";

          // Potential race condition
          // potential solution: clientArrayList.get(username).getPublicKey()
          broadCastMessage(msg + generateCertificate(publicKey), username, false);

          msg = "Current users in chat: ";
          for (int i = 0; i < clientArrayList.size(); i++)
            msg += clientArrayList.get(i).getUsername() + " ";

          sendMessage("connected@" + username, address, port);
          sendMessage(msg, address, port);
          broadCastMessage("(" + username + ") has entered the chat.", username, false);

          // (if the user doesn't already exist)
        } else {
          sendMessage("You are not on the server whitelist. Please restart client and enter valid username.", address, port);
        }

        continue;
      }
      if (!(allowedUsers.contains(currentUser))) // This prevents non-allowed users to send any messages.
        continue;
      if (received.contains("@exit@")) {
        System.out.println("[" + currentUser + "] has disconnected.");
        msg = "has disconnected.";
        for (int i = 0; i < clientArrayList.size(); i++) {
          if (clientArrayList.get(i).getUsername().equals(currentUser))
            clientArrayList.remove(i);
        }
      }

      if (received.contains("@shutdown@")) { // i.e. if a client has told the server to shutdown.
        running = false;
        System.out.println("Server shut down by user: " + currentUser);
        terminating = true;
        msg = "@shutdown@ by user: " + currentUser;
      } else
        msg = "[" + currentUser + "] " + msg; // Any message sent by the client that is not '@end'. Prepend the user's
                                              // message with their username.
      

      broadCastMessage(msg, currentUser, terminating);
     
    }
    socket.close(); // Close the server socket.
  }

  /**
   * Populates the clientArrayList with clients everytime a new client connects. A
   * new user is not added if the user already exists.
   * 
   * @param username The username of the prospective client
   * @param address  The IP address of the prospective client
   * @param port     The port of the prospective client
   */

  private void manageClientBase(String username, InetAddress address, int port) {
    boolean clientPresent = false; // Flag to check for the pre-existence of a user in the client base (i.e.
                                   // contained in ClientArrayList).

    for (int i = 0; i < clientArrayList.size(); i++) { // Loop through the list and if the client already exists, set
                                                       // flag to true.
      if (clientArrayList.get(i).getUsername() == username)
        clientPresent = true;
    }

    if (!(clientPresent))
      clientArrayList.add(new clientObj(username, address, port, publicKey, generateCertificate(publicKey))); // If the
                                                                                                              // client
                                                                                                              // does
                                                                                                              // not yet
                                                                                                              // exist,
    // create a new
    // clientObj and add it to the list.
  }
 
  /**
   * This is a basic function to send a message on the DatagramSocket. This is
   * done through the DatagramSocket.send() method.
   * 
   * @param msg     The message to be sent
   * @param address The IP address to which the message must be sent to
   * @param port    The port to which the message must be sent to
   */

  private void sendMessage(String msg, InetAddress address, int port) {
    // msg = senderThread.buildMessageChecksum(msg);
    buf = msg.getBytes();
    DatagramPacket packet = new DatagramPacket(buf, buf.length, address, port);
    try {
      socket.send(packet); // Send line of chat history
    } catch (IOException e) {
      System.out.println(e);
    }
  }

  /**
   * This auxillary method returns the username of a client with the specified
   * address and port
   * 
   * @param address The address at which the client resides
   * @param port    The port at which the client resides
   * @return The client's username
   */

  private String returnClientUserName(InetAddress address, int port) {
    String sAddress = address.getHostAddress();
    for (int i = 0; i < clientArrayList.size(); i++) {
      if ((clientArrayList.get(i).getStringAddress().equals(sAddress)) && (clientArrayList.get(i).getPort() == port))
        return clientArrayList.get(i).getUsername();
      // Loop through the list and if their exists a client with the same IP and port,
      // return that client's user name
    }
    return "";
  }

  /**
   * This is a basic implementation of a broadcast technique. This is achieved by
   * looping through the whole clientArrayList and sending the message to all
   * connected clients. The caveat to this is that the client who sent the message
   * will not be sent their own message. In the event that the server is shutting
   * down, all users (including the client who sent the @shutdown@ message) will
   * be notified.
   * 
   * @param msg       The message to be sent
   * @param username  The username of the client who sent the original message
   *                  (this is passed so that this client is NOT sent their own
   *                  message)
   * @param terminate Whether the server is shutting down.
   */

  private void broadCastMessage(String msg, String username, boolean terminate) {

    for (int i = 0; i < clientArrayList.size(); i++) { // Loop through the Client List and send the message to every
                                                       // client, besides the client that sent the message.
      // This allows for group chat functionality.

      if (!(clientArrayList.get(i).getUsername().equals(username)) || terminate) {
        sendMessage(msg, clientArrayList.get(i).getInetAddress(), clientArrayList.get(i).getPort());
      }
    }
  }

  private String convertClientPubKeyToString(PGPPublicKeyRing pk) {
    String asciiArmoredPublicKey = "";
    try {
      asciiArmoredPublicKey = PGPainless.asciiArmor(pk);
    } catch (Exception e) {
      // TODO: handle exception
    }
    return asciiArmoredPublicKey;
  }

  private String generateCertificate(PGPPublicKeyRing pk) {
    String msg = "";

    try {
      ByteArrayInputStream in = new ByteArrayInputStream(
          convertClientPubKeyToString(pk).getBytes(StandardCharsets.UTF_8));

      ByteArrayOutputStream out = new ByteArrayOutputStream();

      SigningOptions signingOptions = SigningOptions.get();
      // for cleartext signed messages, we need to add a detached signature...
      signingOptions.addDetachedSignature(keyProtector, certificateAuthorityPrivateKey,
          DocumentSignatureType.CANONICAL_TEXT_DOCUMENT);
      ProducerOptions producerOptions = ProducerOptions.sign(signingOptions)
          .setCleartextSigned(); // and declare that the message will be cleartext signed

      // Create the signing stream
      EncryptionStream signingStream = PGPainless.encryptAndOrSign()
          .onOutputStream(out) // on the output stream
          .withOptions(producerOptions); // with the options

      Streams.pipeAll(in, signingStream); // pipe the plaintext message into the signing stream
      signingStream.close(); // remember to close the stream to finish the signatures

      // Now the output stream contains the signed message
      byte[] signedMessage = out.toByteArray();
      msg = new String(signedMessage);

    } catch (Exception e) {
    
      System.out.println(e);
    }

    return msg;

  }

}

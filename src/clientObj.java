import java.net.InetAddress;

/**
 * This is a simple class used to create a light-weight data storage class for
 * connected clients. Its primary function is to keep track of users currently
 * connected to the server. It is created when a udpClient successfully connects
 * to the udpServer thread and it has several functions that we can use to
 * interact with clients through the server. These are mainly accessor methods
 * such as “getUsername()” or "getCertificate()" which are pivotal in controlling the broadcasting of
 * messages to the appropriate clients.
 * 
 * @author FSHJAR002 RSNJOS005 ARNSHA011 SNDJEM002
 * @since 2022-05-10
 */

public class clientObj { 


  private String userName;
  private InetAddress address;
  private int port;
  private String certificate = null; 

  /**
   * Construction of this object requires the client's username, IP address,
   * certificate and port number.
   * 
   * @param u The client's username
   * @param a The client's IP address
   * @param p The client's port number
   * @param cert The client's certificate
   */

  public clientObj(String u, InetAddress a, int p,  String cert) { // Client is created with their particular username, IP address and
                                                     // port.
    userName = u;
    address = a;
    port = p;
   
    certificate = cert;
  }

  /**
   * Accesor method for returning the client's username
   * 
   * @return The client's username
   */
  public String getUsername() {
    return userName;
  }

    /**
   * Accesor method for returning the client's certificate
   * 
   * @return The client's certificate
   */
  public String getCertificate(){
    return certificate;
  }

  /**
   * Accesor method for returning the client's IP address
   * 
   * Accesor method for returning the
   * @return The client's IP address
   */
  public InetAddress getInetAddress() {
    return address;
  }

  /**
   * Accesor method for returning the client's IP address as a string
   * 
   * @return The client's IP address as a string
   */
  public String getStringAddress() {
    return address.getHostAddress();
  }

  /**
   * Accesor method for returning the client's port number
   * 
   * @return The client's port number
   */
  public int getPort() {
    return port;
  }


 

}

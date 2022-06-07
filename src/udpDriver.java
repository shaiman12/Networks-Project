
/**
 *udpDriver
 *This class is where the main function is called. It has multiple invoking parameters that enable specific startup features.
 *Startup features include a “localhost” start-up which binds the server on the localhost – primarily used for testing,
 *a WAN startup which sets up the server on an external IP address, enabling cross network communication,
 *and a client startup which simply enables a user to interact with the server.
 *The server startup sequence creates a udpServer object and the client startup sequence creates a udpClient object.
 *@author FSHJAR002 RSNJOS005 ARNSHA011 SNDJEM002
 *@since 2022-05-10
 */

public class udpDriver {

  private static udpClient cUdp;
  private static udpServer server;
 
  /**
   *Main function
   *@param args Command line arg
   */
  public static void main(String[] args) {
 
   

   
    switch (args[0].charAt(0)) { 

      case 's': // 's' For server
        switch (args[0]) { 
          case "sWan":
            server = new udpServer("192.168.0.111", 1234); //for wan connection
            break;
          default:
            server = new udpServer("localhost", 1234); //For local connection
            break;
        }
        server.run(); //start server up
       
        break;


      case 'c': // 'c' For client
        

       
        switch (args[0]) {
          case "cWan":
            cUdp = new udpClient("192.168.100.112", 1234, Boolean.parseBoolean(args[1])); //create new udpClient over specifc wan connection.
            break;
          default:
            cUdp = new udpClient("localhost", 1234, Boolean.parseBoolean(args[1])); //create new udpClient over generic local host connection.
            break;
        }

 

        break;
    }
  }
}

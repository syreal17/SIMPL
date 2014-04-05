package server;

import java.io.*;
import java.net.*;

import javax.crypto.SecretKey;

import protocol.Packet;

public class ClientHandlerThread implements Runnable {

	private Server server;
	private Socket clientSocket;
	private InputStream clientStream;
	private SecretKey sessionKey;
	@Override
	public void run() {
		try{
			Object o;
			
			while( true ){
				//remember some variables for thread lifetime
				this.server = CmdLine.server;
				//query the Server's ClientHandler for the unhandled client socket
				this.clientSocket = this.server.getClientHandler().getUnhandledEntry().getClientSocket();
				this.clientStream = this.clientSocket.getInputStream();
							
				//not doing FSM server side for beginning of comm; rather, relying on flags
				byte[] recv = new byte[common.Constants.MAX_EXPECTED_PACKET_SIZE];
				//wait for data from client
				int count = this.clientStream.read(recv);
				//once we have it, truncate down to smallest array
				byte[] clientPacketBytes = new byte[count];
				System.arraycopy(recv, 0, clientPacketBytes, 0, count);
				//make Packet out of bytes
				//TODO: verify viability (first time methodology used)
				o = common.Utils.deserialize(clientPacketBytes);
				Packet clientPacket = (Packet) o;
				//handle the type of packet
				if( clientPacket.flags.contains(Packet.Flag.Login) ){
					this.server.handle_login(clientPacket, clientSocket, this.clientStream);
				} else if( clientPacket.flags.contains(Packet.Flag.Discover) ){
					this.server.handle_discover(clientSocket, this.clientStream, sessionKey);
				} else if( clientPacket.flags.contains(Packet.Flag.Negotiate) ){
					this.server.handle_chat_negotiation();
				} else if( clientPacket.flags.contains(Packet.Flag.Logout) ){
					this.server.handle_logout();
					break;
				} else {
					System.out.println(Server.UNEXPECTED_CLIENT_PACKET_MSG);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
			return;
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			return;
		}
	}
}

package server;

import java.io.*;
import java.net.*;

import javax.crypto.SecretKey;

import protocol.Packet;

public class ClientHandlerThread extends Thread {
	
	private Server server;
	private Socket clientSocket;
	private InputStream clientStream;
	private String clientUsername;
	private byte[] sessionKey;

	//these fields the Server will manipulate when a different ClientHandlerThread wants to talk to this one's Client
	public boolean wanted;
	public String usernameToTalkWith;
	public InetAddress ipToTalkWith;
	
	@Override
	public void run() {
		try{
			this.wanted = false;
			this.usernameToTalkWith = null;
			this.ipToTalkWith = null;
			
			//remember some variables for thread lifetime
			this.server = CmdLine.server;
			//query the Server's ClientHandler for the unhandled client socket
			this.clientSocket = this.server.getClientHandler().getUnhandledEntry().getClientSocket();
			this.clientSocket.setSoTimeout(common.Constants.SO_TIMEOUT);
			this.clientStream = this.clientSocket.getInputStream();
			this.clientUsername = null;
			
			while(true){
				//
				this.checkForNegotiations();
				//the client handle loop is going to return because of SocketTimeoutExceptions fairly frequently.
				this.enterClientHandleLoop();
			}
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	private void checkForNegotiations(){
		
	}
	
	private void enterClientHandleLoop(){
		Object o;
		while( true ){
			try{
				//not doing FSM server side for beginning of comm; rather, relying on flags
				byte[] recv = new byte[common.Constants.MAX_EXPECTED_PACKET_SIZE];
				//wait for data from client
				int count = this.clientStream.read(recv);
				//once we have it, truncate down to smallest array
				byte[] clientPacketBytes = new byte[count];
				System.arraycopy(recv, 0, clientPacketBytes, 0, count);
				//make Packet out of bytes
				o = common.Utils.deserialize(clientPacketBytes);
				Packet clientPacket = (Packet) o;
				//handle the initial packet for each client-server exchange (login, discover, negotiate, logout)
				if( clientPacket.flags.contains(Packet.Flag.Login) ){
					this.clientUsername = this.server.start_handle_login(clientPacket, clientSocket, this.clientStream);
				} else if( clientPacket.flags.contains(Packet.Flag.Discover) ){
					this.server.start_handle_discover(clientSocket, clientPacket, sessionKey);
				} else if( clientPacket.flags.contains(Packet.Flag.Negotiate) ){
					this.server.start_handle_negotiation(clientSocket, clientPacket, sessionKey);
				} else if( clientPacket.flags.contains(Packet.Flag.Logout) ){
					this.server.start_handle_logout();
					break;
				} else {
					System.err.println(Server.UNEXPECTED_CLIENT_PACKET_MSG);
				}
			} catch (SocketTimeoutException e){
				//do nothing if the socket times out. Just return to the run function body
				return;
			} catch (IOException e) {
				e.printStackTrace();
				return;
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
				return;
			}
		}
	}
	
	public boolean isClientUsernameInitialized(){
		if( this.clientUsername == null ){
			return false;
		} else {
			return true;
		}
	}
}

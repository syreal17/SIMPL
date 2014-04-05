package server;

import java.net.*;

/**
 * Used as the entry in a ClientHandler. Simple packaging of a Socket with semantics of it being handled or not
 * @author syreal
 *
 */
public class ClientHandlerEntry {
	private Socket clientSocket;
	private boolean handled;
	
	public ClientHandlerEntry(Socket clientSocket, boolean handled){
		this.clientSocket = clientSocket;
		this.handled = handled;
	}
	
	public boolean isHandled(){
		return this.handled;
	}
	
	public Socket getClientSocket(){
		return this.clientSocket;
	}
}

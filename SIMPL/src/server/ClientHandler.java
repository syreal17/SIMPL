package server;

import java.util.*;

/**
 * Simple class to keep track of all the Server's known sockets and whether they have been handled or not.
 * Key for a new thread knowing which Socket to deal with.
 * ASSUMPTIONS: There is only 
 * @author syreal
 *
 */
public class ClientHandler {
	ArrayList<ClientHandlerEntry> clientEntries;
	
	public ClientHandler() {
		this.clientEntries = new ArrayList<ClientHandlerEntry>();
	}
	
	public void addEntry(ClientHandlerEntry che){
		this.clientEntries.add(che);
	}
	
	/**
	 * Will return the first unhandled Client it finds. It's somewhat undefined what "first unhandled Client" is in
	 * this context. Using a queue would disambiguate, but we don't care enough whether it's actually fifo or not.
	 * @return
	 */
	public ClientHandlerEntry getUnhandledEntry(){
		for( ClientHandlerEntry che : this.clientEntries ){
			if( !che.isHandled() ){
				che.handled();
				return che;
			}
		}
		return null;
	}
}

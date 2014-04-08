package server;

import java.io.Serializable;
import java.util.Map.Entry;

public class UserDBEntry implements Serializable {

	private static final long serialVersionUID = 3345995632362053636L;
	
	private String username;
	private byte[] pwHash;
	
	public UserDBEntry(Entry<String, byte[]> entry){
		this.username = entry.getKey();
		this.pwHash = entry.getValue();
	}
	
	public String getUsername(){
		return this.username;
	}
	
	public byte[] getPwHash(){
		return this.pwHash;
	}
}

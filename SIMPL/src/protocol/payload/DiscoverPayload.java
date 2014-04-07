package protocol.payload;

import java.util.ArrayList;

import common.SimplException;

public class DiscoverPayload extends ClientServerSessionPayload {
	
	private static final long serialVersionUID = 102688147909876831L;
	public ArrayList<String> usernames;
	
	public DiscoverPayload(ArrayList<String> usernames){
		this.usernames = usernames;
	}
	
	@Override
	public void copyFrom(Payload template) throws SimplException{
		if( template instanceof DiscoverPayload){
			DiscoverPayload dpTemplate = (DiscoverPayload) template;
			this.usernames = dpTemplate.usernames;
		} else {
			throw new SimplException("Payload template was not a DiscoverPayload!");
		}
	}
}

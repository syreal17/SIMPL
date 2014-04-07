package protocol.payload;

import common.*;

//TODO: Might even extend ClientServerSession if DH key can be made into byte[]
public class ChatPayload extends Payload {

	private static final long serialVersionUID = -4032008079394447168L;
	
	public String message;
	
	public ChatPayload(String message){
		this.message = message;
	}

	@Override
	public void copyFrom(Payload template) throws SimplException {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}

}

package common;

public class Packet {
	
	//ltj: all of these types enummerated so that the Packets can intelligently
	//		interpret themselves. Much computation is pushed to the Packet object
	public static enum Type {
		HELLO, HELLOCHALLENGE, HELLORESPONSE, 	//slide 5 in SIMPLv2
		DISCOVER, DISCOVERED,					//slide 6 in SIMPLv2
		CHATREQ, SERVCHATREQ, CHATRESP, SERVCHATRESP, CHAT,	//slide 7
		LEAVE, LEAVEACK,						//slide 8
		LOGOUT, LOGOUTACK						//slide 9
	}
	
	
}

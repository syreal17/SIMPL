package common;

public class Packet {
	
	//ltj: all these types might not be needed, esp. the different types
	//		for client->server and server->client
	public static enum Type {
		HELLO, HELLOCHALLENGE, HELLORESPONSE, 	//slide 5 in SIMPLv2
		DISCOVER, DISCOVERED,					//slide 6 in SIMPLv2
		CHATREQ, SERVCHATREQ, CHATRESP, SERVCHATRESP, CHAT,	//slide 7
		LOGOUT, LOGOUTACK						//slide 8
	}
	
	
}

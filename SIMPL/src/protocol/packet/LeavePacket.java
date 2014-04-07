package protocol.packet;

/**
 * I think this is currently vulnerable to TCP hijacking to do a denial of service
 * To fix it, we would have to:
 * 		1. Encrypt and decrypt these packets
 * 		2. Ensure that encrypted LeavePackets look different every time they are encrypted
 *
 */
public class LeavePacket extends Packet {

	private static final long serialVersionUID = 917649278682126231L;

}

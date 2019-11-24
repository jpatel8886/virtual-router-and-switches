package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.MACAddress;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import java.io.*;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device
{	

	long prevTime, currTime;
	Map <MACAddress, Iface> switchTable = new HashMap<>();

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " + etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/

		MACAddress srcMAC = etherPacket.getSourceMAC();
		MACAddress destMAC = etherPacket.getDestinationMAC();

		// interfaces of this switch (data structure inherited from parent)
		Map<String, Iface> localPorts = getInterfaces();

		// TIMER expired, clear the data structure and re-learn the src of the packet
		currTime = System.currentTimeMillis(); 

		if ((currTime-prevTime)/1000 > 15) {
			switchTable.clear(); 
			switchTable.put(srcMAC, inIface); // FORGET
		}	
		else {
			// check if src is in the data structure, learn it if not
			if (!switchTable.containsKey(srcMAC)) {
				switchTable.put(srcMAC, inIface);
				prevTime = currTime;
			}
		}
	
		// if switchTable contains destination MAC, FORWARD it
		if (switchTable.containsKey(destMAC)) {
			Iface destPort = switchTable.get(destMAC);
			sendPacket(etherPacket, destPort);
		}

		else {
			// flood over all interfaces minus the recieving port
			for (Iface value : localPorts.values()) {
				if (value != inIface) sendPacket(etherPacket, value);
			}
		}

		/********************************************************************/
	}
}

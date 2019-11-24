package edu.wisc.cs.sdn.vnet.rt;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import java.util.HashMap;
import java.util.Map;


/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }

	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/

		//////////////////////////////////////////////////////////////////////			
		// Verify TTL and Checksum
		//////////////////////////////////////////////////////////////////////

		// drop the packet if not IPv4		
		if (etherPacket.getEtherType() != etherPacket.TYPE_IPv4) {
			System.out.println("IPv4 not valid, dropping the packet"); 
			return;
		} 		

		// this gives us the header of the ether packet 
		IPv4 packet = (IPv4)etherPacket.getPayload(); 

		byte headerLength = packet.getHeaderLength();
		short savedChecksum = packet.getChecksum(); 

		// set checkSum to zero, in order to re-compute it
		short zero = 0;
		packet.setChecksum(zero); 

		// check if new checkSum matches saved checksum, drop if it doesn't 
		packet.serialize();  // re-computes the sum of header and fills checksum again

		if (packet.getChecksum() != savedChecksum) {	
			System.out.println("checksum not valid, dropping the packet"); 
			return;
		} 		

		// valid packet, decrement TTL
		else {
			byte currTTL = packet.getTtl();
			currTTL = (byte)(currTTL - 1);
			packet.setTtl(currTTL);

			// if TTL expired, drop the packet
			if (currTTL == 0) {
				System.out.println("TTL not valid, dropping the packet"); 
				return;
			} 

			//calculate checksum again after decrementing TTL
			packet.setChecksum(zero);
			packet.serialize();
		}
	
		/////////////////////////////////////////////////////////////////////////
		// Verify the destination IP and drop it if it matches Router's interface
		/////////////////////////////////////////////////////////////////////////

		// where is this packet headed?
		int destIP = packet.getDestinationAddress(); 

		// MAP of this device (router) that contains MAC keys, Iface values
		Map <String,Iface> localports = getInterfaces(); 		

		// iterate through the Ifaces
		for (Iface val : localports.values()) {

			// if Router's interface's IP matches packet's IP, drop the packet
			if (val.getIpAddress() == destIP) {
				System.out.println("Packet tried to go to Router's interface, dropping the invalid packet"); 
				return;
			}
		}

		//////////////////////////////////////////////////////////////////////////
		// Forward the packet 
		//////////////////////////////////////////////////////////////////////////		

		// look up an entry from Router Table
		RouteEntry match = routeTable.lookup(destIP); 

		int gatewayIP = match.getGatewayAddress();

		// if no entries found, drop the packet
		if (match == null) {
			System.out.println("No entries found in RouteTable, dropping the packet"); 
			return; 
		}

		// Forwarding Packet (given all requirements are met)

		ArpEntry arpEntry;

		// get ARP Cache Look-up entry
		if (gatewayIP == 0) arpEntry = arpCache.lookup(destIP); 	
		else arpEntry = arpCache.lookup(gatewayIP);   

		// String version of ARP Entry
		String arpMAC = arpEntry.getMac().toString(); 

		// update ethernet packet headers (Source MAC and Dest. MAC)
		Iface destinationIface = match.getInterface();

		etherPacket.setSourceMACAddress(destinationIface.getMacAddress().toString());
		etherPacket.setDestinationMACAddress(arpMAC); 

		//calculate checksum again after altering the MAC fields
		packet.setChecksum(zero);
		packet.serialize();

		// SEND THE PACKET 
		boolean ret = super.sendPacket(etherPacket, destinationIface); 

		/********************************************************************/
	}
}







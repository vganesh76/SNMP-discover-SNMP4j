package com.snmp.test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.Null;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

public class SNMPDiscover {

	//private static String ip = "127.0.0.1";
	private static String ipAddress = "localhost";
	private static int port = 161;
    private static int    snmpVersion  = SnmpConstants.version2c;
    private static String  community  = "public";
    
    //ROOT of Management tree
    private static String  oidValue  = ".1.3.6.1.2";  
    
	public static void main(String[] args) {
		SNMPDiscover obj = new SNMPDiscover();
		List<VariableBinding> vList = obj.walk(new OID(oidValue), community);
		System.out.println("vList size= "+vList.size());
		for(int i = 0; i < vList.size(); i++) {
			VariableBinding v = vList.get(i);
			System.out.println("v.getOid()= "+v.getOid()+" syntax= "+v.getVariable().getSyntaxString());
		}
	}
	

	/**
	 * A method used to walk the OID from Management Tree.
	 * @param oid
	 * @param community
	 * @return
	 */
	public List<VariableBinding> walk(OID oid, String community) {
		System.out.println("Inside walk()");
        List<VariableBinding> ret = new ArrayList<VariableBinding>();

        PDU requestPDU = new PDU();
        requestPDU.add(new VariableBinding(oid));
        requestPDU.setType(PDU.GETNEXT);

        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString(community));
        Address address = GenericAddress.parse("udp:" + ipAddress + "/" + port);
        target.setAddress(address);
        target.setVersion(snmpVersion);
        target.setTimeout(3000);

        try {
            TransportMapping transport;
                transport = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transport);
            transport.listen();

            boolean finished = false;

            while (!finished) {
                VariableBinding vb = null;

                ResponseEvent respEvt = snmp.send(requestPDU, target);
                PDU responsePDU = respEvt.getResponse();
                if (responsePDU != null) {
                    vb = responsePDU.get(0);
                }

                if (responsePDU == null) {
                    finished = true;
                } else if (responsePDU.getErrorStatus() != 0) {
                    finished = true;
                } else if (vb.getOid() == null) {
                    finished = true;
                } else if (vb.getOid().size() < oid.size()) {
                    finished = true;
                } else if (oid.leftMostCompare(oid.size(), vb.getOid()) != 0) {
                    finished = true;
                } else if (Null.isExceptionSyntax(vb.getVariable().getSyntax())) {
                    finished = true;
                } else if (vb.getOid().compareTo(oid) <= 0) {
                    finished = true;
                } else {
                    ret.add(vb);
                    requestPDU.setRequestID(new Integer32(0));
                    requestPDU.set(0, vb);
                }
            }
            snmp.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return ret;
    }	
}

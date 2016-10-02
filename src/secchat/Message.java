package secchat;

import java.io.Serializable;

public class Message implements Serializable {
	
	protected static final long serialVersionUID = 1112122200L;
	
	//kryptografhmena to secret key kai h synopsh tou mhnumatos
	private String sData;
	//to sData ypogegrameno
	private byte[] signature;
	//kryptografhmeno ChatMessage
	private byte[] EnChatMessage;
	
	public Message(byte[] EnChatMessage, String signeddata, byte[] signature){
		this.EnChatMessage = EnChatMessage;
		this.signature = signature;
		this.sData = signeddata;
	}

	public String getSData() {
		return sData;
	}

	public void setSData(String sData) {
		this.sData = sData;
	}

	public byte[] getSignature() {
		return signature;
	}

	public void setSignature(byte[] signature) {
		this.signature = signature;
	}

	public byte[] getEnChatMessage() {
		return EnChatMessage;
	}

	public void setEnChatMessage(byte[] EnChatMessage) {
		this.EnChatMessage = EnChatMessage;
	}
}

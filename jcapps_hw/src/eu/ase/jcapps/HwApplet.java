/** 
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 * 
 */

package eu.ase.jcapps;

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.annotations.*;
import javacardx.crypto.Cipher;

import static eu.ase.jcapps.HwAppletStrings.*;

/**
 * Applet class
 * 
 * @author <user>
 */
@StringPool(value = { @StringDef(name = "Package", value = "eu.ase.jcapps"),
		@StringDef(name = "AppletName", value = "HwApplet") },
		// Insert your strings here
		name = "HwAppletStrings")
public class HwApplet extends Applet {

	private static final byte CLA_APP = (byte) 0x80;
	private static final byte INS_ENC = (byte) 0x50;
	private static final byte INS_DEC = (byte) 0x60;
	
	private static final byte[] key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

	private Cipher cipher;
	private AESKey secretKey;
	
	private byte[] volatileMem;

	/**
	 * Installs this applet.
	 * 
	 * @param bArray  the array containing installation parameters
	 * @param bOffset the starting offset in bArray
	 * @param bLength the length in bytes of the parameter data in bArray
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new HwApplet();
	}

	/**
	 * Only this class's install method should create the applet object.
	 */
	protected HwApplet() {
		cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		
		secretKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		secretKey.setKey(key, (short)0);

		volatileMem = JCSystem.makeTransientByteArray((short)0x10, JCSystem.CLEAR_ON_DESELECT);
		
		register();
	}

	public void encrypt(APDU apdu) {
		byte[] buffer = apdu.getBuffer();

		byte init = buffer[ISO7816.OFFSET_P1];
		byte isFinal = buffer[ISO7816.OFFSET_P2];
		
		short bytesRead = apdu.setIncomingAndReceive();
		
		if(bytesRead != 16) {
			if(isFinal == 0) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
		}

		if(init != 0) {
			cipher.init(secretKey, Cipher.MODE_ENCRYPT, key, (short)0, (short)16);
		}
		
		if(isFinal == 0) {
			cipher.update(buffer, ISO7816.OFFSET_CDATA, bytesRead, buffer, (short)0);
		} else {
			if(bytesRead != 16) {
				byte padding = (byte) (16 - bytesRead);
				
				for(byte i = 0; i < bytesRead; ++i) {
					volatileMem[i] = buffer[ISO7816.OFFSET_CDATA + i];
				}
				
				for(byte i = (byte)bytesRead; i < 16; ++i) {
					volatileMem[i] = padding;
				}
				
				cipher.doFinal(volatileMem, (short)0, (short)16, buffer, (short)0);
			} else {
				cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, bytesRead, buffer, (short)0);
			}
		}

		apdu.setOutgoingAndSend((short) 0, (short) 16);
	}
	
	public void decrypt(APDU apdu) {
		byte[] buffer = apdu.getBuffer();

		byte init = buffer[ISO7816.OFFSET_P1];
		byte isFinal = buffer[ISO7816.OFFSET_P2];
		
		short bytesRead = apdu.setIncomingAndReceive();
		
		if(bytesRead != 16) {
			if(isFinal == 0) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
		}

		if(init != 0) {
			cipher.init(secretKey, Cipher.MODE_DECRYPT, key, (short)0, (short)16);
		}
		
		if(isFinal == 0) {
			cipher.update(buffer, ISO7816.OFFSET_CDATA, bytesRead, buffer, (short)0);
		} else {
			cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, bytesRead, buffer, (short)0);
		}

		apdu.setOutgoingAndSend((short) 0, (short) 16);
	}

	/**
	 * Processes an incoming APDU.
	 * 
	 * @see APDU
	 * @param apdu the incoming APDU
	 */
	@Override
	public void process(APDU apdu) {
		if (selectingApplet() || reSelectingApplet()) {
			return;
		}

		byte[] buffer = apdu.getBuffer();

		if (buffer[ISO7816.OFFSET_CLA] != CLA_APP) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch (buffer[ISO7816.OFFSET_INS]) {
		case INS_ENC:
			encrypt(apdu);
			return;
		case INS_DEC:
			decrypt(apdu);
			return;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}

	}
}

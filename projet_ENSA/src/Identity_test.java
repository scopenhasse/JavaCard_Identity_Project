import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public class Identity_test {

	public static AID appletAID;
	public static CardSimulator simulator;

	final static byte[] macKey = { 1, 2, 3, 4, 5, 6, 7, 8 };
	final static byte[] CipherKey = { 1, 2, 2, 1, 4, 6, 6, 4 };

	public static DESKey macDesKey;
	public static DESKey CipherDesKey;
	public static Cipher m_encryptCipherMAC;
	public static Cipher m_encryptCipher;

	public static void main(String[] args) {

		// 1. Create simulator
		simulator = new CardSimulator();

		// 2. Install Select applet
		installSelectApplet();

		macDesKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
		CipherDesKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
		macDesKey.setKey(macKey, (short) 0);
		CipherDesKey.setKey(CipherKey, (short) 0);

		m_encryptCipherMAC = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		m_encryptCipherMAC.init(macDesKey, Cipher.MODE_ENCRYPT);

		m_encryptCipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		m_encryptCipher.init(CipherDesKey, Cipher.MODE_ENCRYPT);

		// 3. tests
		testStoreReadData();

	}

	private static void installSelectApplet() {

		// 1- Install applet
		appletAID = AIDUtil.create("F000000001");
		simulator.installApplet(appletAID, Identity.class);

		// 2- Select applet
		System.out.println("Selecting Applet...");
		simulator.selectApplet(appletAID);
		System.out.println("Applet Selected with AID : F000000001");
	}

	private static void testStoreReadData() {
		testWrongCLA_STORE_DATA();
		testWrongP1_STORE_DATA();
		testWrongP2_STORE_DATA();
		testWrongLcVsP2_Nom_STORE_DATA();
		testWrongLcVsP2_Prenom_STORE_DATA();
		testWrongLcVsP2_DateNaissance1_STORE_DATA();
		testWrongLcVsP2_DateNaissance2_STORE_DATA();
		testWrongLcVsP2_ID1_STORE_DATA();
		testWrongLcVsP2_ID2_STORE_DATA();
		
		testWrongCLA_READ_DATA();
		testWrongP1_READ_DATA();
		testWrongP2_READ_DATA();
		testWrongLeVsP2_NomPrenom1_READ_DATA();
		testWrongLeVsP2_DateNaissance_READ_DATA();
		testWrongLeVsP2_ID_READ_DATA();
		
		testGood_Nom_Prenom_STORE_READ_DATA();
		testGood_Date_STORE_READ_DATA();
		testGood_ID_STORE_READ_DATA();
		
		testWrongCLA_UPDATE_DATE();
		testWrongP1_UPDATE_DATE();
		testWrongP2_UPDATE_DATE();
		testWrongLc_UPDATE_DATE();
		testWrongMAC_UPDATE_DATE();
		testGoodData_UPDATE_DATE();
		
		testWrongCLA_UPDATE_ID();
		testWrongP1_UPDATE_ID();
		testWrongP2_UPDATE_ID();
		testWrongLc_UPDATE_ID();
		testGoodData_UPDATE_ID();
		
		testINSNotSupported();

	}

	private static void testWrongCLA_STORE_DATA() {
		System.out.println("**************************************");
		System.out.println("test Wrong CLA STORE_DATA, start ...");
		int cla = 0x40;
		int ins = 0x10;
		int p1 = 0x05;
		int p2 = 0x05;
		byte[] data = { 7, 5, 7, 8, 2, 1, 2, 3, 7, 5, 7, 8, 2, 1, 2, 3 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU STORE_DATA ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");

		System.out.println("SW : " + Integer.toHexString(sw));
		// Check response status word
		if (0x6E00 == sw)
			System.out.println("test Wrong CLA STORE_DATA, ended PASS ...");
		else
			System.out.println("test Wrong CLA STORE_DATA, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongP1_STORE_DATA() {
		System.out.println("**************************************");
		System.out.println("test WrongP1 STORE_DATA, start...");
		int cla = 0x00;
		int ins = 0x10;
		int p1 = 0x01;
		int p2 = 0x00;
		byte[] data = { 7, 5, 7, 8, 2, 1, 2, 3 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU STORE_DATA ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x6B00 == sw)
			System.out.println("test WrongP1 STORE_DATA, ended PASS ...");
		else
			System.out.println("test WrongP1 STORE_DATA, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongP2_STORE_DATA() {
		System.out.println("**************************************");
		System.out.println("test WrongP2 STORE_DATA, start...");
		int cla = 0x00;
		int ins = 0x10;
		int p1 = 0x00;
		int p2 = 0x05;
		byte[] data = { 7, 5, 7, 8, 2, 1, 2, 3 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU STORE_DATA ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x6B00 == sw)
			System.out.println("test WrongP2 STORE_DATA, ended PASS ...");
		else
			System.out.println("test WrongP2 STORE_DATA, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongLcVsP2_Nom_STORE_DATA() {
		System.out.println("**************************************");
		System.out.println("test WrongLcVsP2 Nom STORE_DATA, start...");
		int cla = 0x00;
		int ins = 0x10;
		int p1 = 0x00;
		int p2 = 0x01;
		byte[] data = { 7, 5, 7, 8, 2, 1, 2, 3, 5, 7, 8, 2, 1, 2, 3 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU STORE_DATA ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x6700 == sw)
			System.out.println("test WrongLcVsP2 Nom STORE_DATA, ended PASS ...");
		else
			System.out.println("test WrongLcVsP2 Nom STORE_DATA, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongLcVsP2_Prenom_STORE_DATA() {
		System.out.println("**************************************");
		System.out.println("test WrongLcVsP2 Prenom STORE_DATA, start...");
		int cla = 0x00;
		int ins = 0x10;
		int p1 = 0x00;
		int p2 = 0x02;
		byte[] data = { 7, 5, 7, 8, 2, 1, 2, 3, 5, 7, 8, 2, 1, 2, 3 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU STORE_DATA ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x6700 == sw)
			System.out.println("test WrongLcVsP2 Prenom STORE_DATA, ended PASS ...");
		else
			System.out.println("test WrongLcVsP2 Prenom STORE_DATA, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongLcVsP2_DateNaissance1_STORE_DATA() {
		System.out.println("**************************************");
		System.out.println("test WrongLcVsP2 DateNaissance STORE_DATA, start...");
		int cla = 0x00;
		int ins = 0x10;
		int p1 = 0x00;
		int p2 = 0x03;
		byte[] data = { 7, 5 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU STORE_DATA ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x6700 == sw)
			System.out.println("test WrongLcVsP2 DateNaissance STORE_DATA, ended PASS ...");
		else
			System.out.println("test WrongLcVsP2 DateNaissance STORE_DATA, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongLcVsP2_DateNaissance2_STORE_DATA() {
		System.out.println("**************************************");
		System.out.println("test WrongLcVsP2 DateNaissance2 STORE_DATA, start...");
		int cla = 0x00;
		int ins = 0x10;
		int p1 = 0x00;
		int p2 = 0x03;
		byte[] data = { 7, 5, 7, 8, 2 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU STORE_DATA ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x6700 == sw)
			System.out.println("test WrongLcVsP2 DateNaissance2 STORE_DATA, ended PASS ...");
		else
			System.out.println("test WrongLcVsP2 DateNaissance2 STORE_DATA, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongLcVsP2_ID1_STORE_DATA() {
		System.out.println("**************************************");
		System.out.println("test WrongLcVsP2 ID1 STORE_DATA, start...");
		int cla = 0x00;
		int ins = 0x10;
		int p1 = 0x00;
		int p2 = 0x04;
		byte[] data = { 7, 5, 7, 8, 2 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU STORE_DATA ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " " + String.format("%02X", 8));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x6700 == sw)
			System.out.println("test WrongLcVsP2 ID1 STORE_DATA, ended PASS ...");
		else
			System.out.println("test WrongLcVsP2 ID1 STORE_DATA, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongLcVsP2_ID2_STORE_DATA() {
		System.out.println("**************************************");
		System.out.println("test WrongLcVsP2 ID1 STORE_DATA, start...");
		int cla = 0x00;
		int ins = 0x10;
		int p1 = 0x00;
		int p2 = 0x04;
		byte[] data = { 7, 5, 7, 8, 2, 5, 7, 8, 2 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU STORE_DATA ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x6700 == sw)
			System.out.println("test WrongLcVsP2 ID2 STORE_DATA, ended PASS ...");
		else
			System.out.println("test WrongLcVsP2 ID2 STORE_DATA, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testGood_Nom_Prenom_STORE_READ_DATA() {
		System.out.println("**************************************");
		System.out.println("test Good_Nom_Prenom STORE_DATA, start...");
		int cla = 0x00;
		int ins = 0x10;
		int p1 = 0x00;
		int p2 = 0x01;
		byte[] Nom = { 7, 5, 7 };
		byte[] Prenom = { 7, 5, 7 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, Nom);
		System.out.println("APDU STORE_DATA nom ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", Nom.length));
		for (int i = 0; i < Nom.length; i++)
			System.out.print(" " + String.format("%02X", Nom[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x9000 == sw) {
			p2 = 0x02;
			commandAPDU = new CommandAPDU(cla, ins, p1, p2, Prenom);
			System.out.println("APDU STORE_DATA Prenom ...");
			response = simulator.transmitCommand(commandAPDU);
			sw = response.getSW();
			System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
					+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
					+ String.format("%02X", Prenom.length));
			for (int i = 0; i < Prenom.length; i++)
				System.out.print(" " + String.format("%02X", Prenom[i]));
			System.out.println("");
			System.out.println("SW : " + Integer.toHexString(sw));

			if (0x9000 == sw) {
				System.out.println("test Good_Nom_Prenom STORE_DATA, SW is OK ...");
				System.out.println("Read Data to check...");
				System.out.println("APDU READ_DATA ...");
				ins = 0x20;
				int le = Nom.length + Prenom.length;
				commandAPDU = new CommandAPDU(cla, ins, p1, p2, le);
				response = simulator.transmitCommand(commandAPDU);
				sw = response.getSW();
				byte[] nomPrenom = response.getData();
				System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
						+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
						+ String.format("%02X", nomPrenom.length));
				for (int i = 0; i < nomPrenom.length; i++)
					System.out.print(" " + String.format("%02X", nomPrenom[i]));
				System.out.println("");
				System.out.println("SW : " + Integer.toHexString(sw));

				if ((Util.arrayCompare(nomPrenom, (short) 0, Nom, (short) 0, (short) Nom.length) == 0)
						&& (Util.arrayCompare(nomPrenom, (short) (Nom.length), Prenom, (short) 0,
								(short) Prenom.length) == 0)) {
					System.out.println("test Good_Nom_Prenom STORE_READ_DATA, Data Read back is OK ...");
					System.out.println("test Good_Nom_Prenom STORE_READ_DATA, ended PASS ...");
				} else {
					System.out.println("test Good_Nom_Prenom STORE_READ_DATA, Data Read back is FAIL ...");
					System.out.println("test Good_Nom_Prenom STORE_READ_DATA, ended FAIL ...");
				}
			} else
				System.out.println("test Good_Nom_Prenom STORE_READ_DATA, ended FAIL ...");

		} else
			System.out.println("test Good_Nom_Prenom STORE_READ_DATA, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testGood_Date_STORE_READ_DATA() {
		System.out.println("**************************************");
		System.out.println("test Good_Date STORE_DATA, start...");
		int cla = 0x00;
		int ins = 0x10;
		int p1 = 0x00;
		int p2 = 0x03;
		byte[] DateNaissance = { 0x12, 0x03, 0x20, 0x01 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, DateNaissance);
		System.out.println("APDU STORE_DATA DateNaissance ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", DateNaissance.length));
		for (int i = 0; i < DateNaissance.length; i++)
			System.out.print(" " + String.format("%02X", DateNaissance[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word and data read back value
		if (0x9000 == sw) {
			System.out.println("test Good_Date STORE_DATA, SW is OK ...");
			System.out.println("Read Data to check...");
			System.out.println("APDU READ_DATA ...");
			ins = 0x20;
			int le = 4;
			commandAPDU = new CommandAPDU(cla, ins, p1, p2, le);
			response = simulator.transmitCommand(commandAPDU);
			sw = response.getSW();
			byte[] ReadDate = response.getData();
			if (ReadDate.length == 4) {
				System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
						+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
						+ String.format("%02X", ReadDate.length));
				for (int i = 0; i < ReadDate.length; i++)
					System.out.print(" " + String.format("%02X", ReadDate[i]));
				System.out.println("");
				System.out.println("SW : " + Integer.toHexString(sw));

				if (Util.arrayCompare(ReadDate, (short) 0, DateNaissance, (short) 0, (short) ReadDate.length) == 0) {
					System.out.println("test Good_Date STORE_READ_DATA, Data Read back is OK ...");
					System.out.println("test Good_Date STORE_READ_DATA, ended PASS ...");
				} else {
					System.out.println("test Good_Date STORE_READ_DATA, Data Read back is FAIL ...");
					System.out.println("test Good_Date STORE_READ_DATA, ended FAIL ...");
				}
			} else
				System.out.println(
						"test Good_Date STORE_READ_DATA, ended FAIL (data read back length is not correct: different from 4 ...");
		} else
			System.out.println("test Good_Date STORE_READ_DATA, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testGood_ID_STORE_READ_DATA() {
		System.out.println("**************************************");
		System.out.println("test Good_ID STORE_DATA, start...");
		int cla = 0x00;
		int ins = 0x10;
		int p1 = 0x00;
		int p2 = 0x04;
		byte[] ID = { 0xA, 1, 2, 3, 4, 5, 6, 7 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, ID);
		System.out.println("APDU STORE_DATA ID ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " " + String.format("%02X", ID.length));
		for (int i = 0; i < ID.length; i++)
			System.out.print(" " + String.format("%02X", ID[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word and data read back value
		if (0x9000 == sw) {
			System.out.println("test Good_ID STORE_DATA, SW is OK ...");
			System.out.println("Read Data to check...");
			System.out.println("APDU READ_DATA ...");
			ins = 0x20;
			int le = 8;
			commandAPDU = new CommandAPDU(cla, ins, p1, p2, le);
			response = simulator.transmitCommand(commandAPDU);
			sw = response.getSW();
			byte[] ReadDate = response.getData();
			if (ReadDate.length == 8) {
				System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
						+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
						+ String.format("%02X", ReadDate.length));
				for (int i = 0; i < ReadDate.length; i++)
					System.out.print(" " + String.format("%02X", ReadDate[i]));
				System.out.println("");
				System.out.println("SW : " + Integer.toHexString(sw));

				if (Util.arrayCompare(ReadDate, (short) 0, ID, (short) 0, (short) ReadDate.length) == 0) {
					System.out.println("test Good_ID STORE_READ_DATA, Data Read back is OK ...");
					System.out.println("test Good_ID STORE_READ_DATA, ended PASS ...");
				} else {
					System.out.println("test Good_ID STORE_READ_DATA, Data Read back is FAIL ...");
					System.out.println("test Good_ID STORE_READ_DATA, ended FAIL ...");
				}
			} else {
				if (ReadDate.length != 0) {
					System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins)
							+ " " + String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
							+ String.format("%02X", ReadDate.length));
					for (int i = 0; i < ReadDate.length; i++)
						System.out.print(" " + String.format("%02X", ReadDate[i]));
					System.out.println("");
					System.out.println("SW : " + Integer.toHexString(sw));
				} else {
					System.out.println("");
					System.out.println("SW : " + Integer.toHexString(sw));
				}
				System.out.println(
						"test Good_ID STORE_READ_DATA, ended FAIL (data read back length is not correct: lenght is not equal to 8)!");
			}

		} else
			System.out.println("test Good_ID STORE_READ_DATA, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongCLA_READ_DATA() {
		System.out.println("**************************************");
		System.out.println("test Wrong CLA READ_DATA, start ...");
		int cla = 0x40;
		int ins = 0x20;
		int p1 = 0x02;
		int p2 = 0x05;
		int le = 0x20;

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, le);
		System.out.println("APDU READ_DATA ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		byte[] dataRead = response.getData();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " " + String.format("%02X", le));
		if (dataRead.length != 0) {
			for (int i = 0; i < dataRead.length; i++)
				System.out.print(" " + String.format("%02X", dataRead[i]));
			System.out.println("");
			System.out.println("SW : " + Integer.toHexString(sw));
			System.out.println("test Wrong CLA READ_DATA, ended FAIL (wrong data sent back) ...");
		} else {
			System.out.println("");
			System.out.println("SW : " + Integer.toHexString(sw));
		}

		// Check response status word
		if (0x6E00 == sw)
			System.out.println("test Wrong CLA READ_DATA, ended PASS ...");
		else
			System.out.println("test Wrong CLA READ_DATA, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongP1_READ_DATA() {
		System.out.println("**************************************");
		System.out.println("test Wrong P1 READ_DATA, start ...");
		int cla = 0x00;
		int ins = 0x20;
		int p1 = 0x03;
		int p2 = 0x01;
		int le = 0x20;

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, le);
		System.out.println("APDU READ_DATA ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		byte[] dataRead = response.getData();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " " + String.format("%02X", le));
		if (dataRead.length != 0) {
			for (int i = 0; i < dataRead.length; i++)
				System.out.print(" " + String.format("%02X", dataRead[i]));
			System.out.println("");
			System.out.println("SW : " + Integer.toHexString(sw));
			System.out.println("test Wrong P1 READ_DATA, ended FAIL (wrong data sent back) ...");
		} else {
			System.out.println("");
			System.out.println("SW : " + Integer.toHexString(sw));
		}

		// Check response status word
		if (0x6B00 == sw)
			System.out.println("test Wrong P1 READ_DATA, ended PASS ...");
		else
			System.out.println("test Wrong P1 READ_DATA, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongP2_READ_DATA() {
		System.out.println("**************************************");
		System.out.println("test Wrong P2 READ_DATA, start ...");
		int cla = 0x00;
		int ins = 0x20;
		int p1 = 0x00;
		int p2 = 0x08;
		int le = 0x20;

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, le);
		System.out.println("APDU READ_DATA ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		byte[] dataRead = response.getData();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " " + String.format("%02X", le));
		if (dataRead.length != 0) {
			for (int i = 0; i < dataRead.length; i++)
				System.out.print(" " + String.format("%02X", dataRead[i]));
			System.out.println("");
			System.out.println("SW : " + Integer.toHexString(sw));
			System.out.println("test Wrong P2 READ_DATA, ended FAIL (wrong data sent back) ...");
		} else {
			System.out.println("");
			System.out.println("SW : " + Integer.toHexString(sw));
		}

		// Check response status word
		if (0x6B00 == sw)
			System.out.println("test Wrong P2 READ_DATA, ended PASS ...");
		else
			System.out.println("test Wrong P2 READ_DATA, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongLeVsP2_NomPrenom1_READ_DATA() {
		System.out.println("**************************************");
		System.out.println("test WrongLeVsP2 NomPrenom READ_DATA, start ...");
		int cla = 0x00;
		int ins = 0x10;
		int p1 = 0x00;
		int p2 = 0x01;
		int le = 0x20;
		byte[] Nom = { 7, 5, 7, 5, 10, 1, 2, 3, 8 };
		byte[] Prenom = { 7, 5, 7, 5, 7, 5, 10, 1, 2, 3, 8 };

		// Store Nom
		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, Nom);
		System.out.println("APDU STORE_DATA nom ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", Nom.length));
		for (int i = 0; i < Nom.length; i++)
			System.out.print(" " + String.format("%02X", Nom[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));
		if (0x9000 == sw) {
			// Store Prénom
			p2 = 0x02;
			commandAPDU = new CommandAPDU(cla, ins, p1, p2, Prenom);
			System.out.println("APDU STORE_DATA nom ...");
			response = simulator.transmitCommand(commandAPDU);
			sw = response.getSW();
			System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
					+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
					+ String.format("%02X", Prenom.length));
			for (int i = 0; i < Prenom.length; i++)
				System.out.print(" " + String.format("%02X", Prenom[i]));
			System.out.println("");
			System.out.println("SW : " + Integer.toHexString(sw));

			if (0x9000 == sw) {
				ins = 0x20;
				commandAPDU = new CommandAPDU(cla, ins, p1, p2, le);
				System.out.println("APDU READ_DATA ...");
				response = simulator.transmitCommand(commandAPDU);
				sw = response.getSW();
				byte[] dataRead = response.getData();
				System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
						+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
						+ String.format("%02X", le));
				if (dataRead.length != 0) {
					for (int i = 0; i < dataRead.length; i++)
						System.out.print(" " + String.format("%02X", dataRead[i]));
					System.out.println("");
					System.out.println("SW : " + Integer.toHexString(sw));
					System.out.println("test Wrong P2 READ_DATA, ended FAIL (wrong data sent back) ...");
				} else {
					System.out.println("");
					System.out.println("SW : " + Integer.toHexString(sw));
				}

				// Check response status word
				if (0x6C20 == sw)
					System.out.println("test WrongLeVsP2 READ_DATA, ended PASS ...");
				else
					System.out.println("test WrongLeVsP2 READ_DATA, ended FAIL ...");
			} else
				System.out.println("test WrongLeVsP2 READ_DATA, ended FAIL (Store Prenom Failed) ...");
		} else
			System.out.println("test WrongLeVsP2 READ_DATA, ended FAIL (Store Nom Failed) ...");
		System.out.println("**************************************");
	}

	private static void testWrongLeVsP2_DateNaissance_READ_DATA() {
		System.out.println("**************************************");
		System.out.println("test WrongLeVsP2 DateNaissance READ_DATA, start ...");
		int cla = 0x00;
		int ins = 0x10;
		int p1 = 0x00;
		int p2 = 0x03;
		int le = 0x07;
		byte[] DateNaissance = { 0x09, 0x04, 0x19, 0x75 };

		// Store Date de naissance
		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, DateNaissance);
		System.out.println("APDU STORE_DATA DateNaissance ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", DateNaissance.length));
		for (int i = 0; i < DateNaissance.length; i++)
			System.out.print(" " + String.format("%02X", DateNaissance[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));
		if (0x9000 == sw) {
			System.out.println("Read Data WrongLeVsP2 DateNaissance...");
			System.out.println("APDU READ_DATA ...");
			ins = 0x20;
			commandAPDU = new CommandAPDU(cla, ins, p1, p2, le);
			response = simulator.transmitCommand(commandAPDU);
			sw = response.getSW();
			byte[] ReadDate = response.getData();
			if (ReadDate.length != 0) {
				for (int i = 0; i < ReadDate.length; i++)
					System.out.print(" " + String.format("%02X", ReadDate[i]));
				System.out.println("");
				System.out.println("SW : " + Integer.toHexString(sw));
				System.out.println("test WrongLeVsP2 DateNaissanceREAD_DATA, ended FAIL (wrong data sent back) ...");
			} else {
				System.out.println("");
				System.out.println("SW : " + Integer.toHexString(sw));
			}

			// Check response status word
			if (0x6C04 == sw)
				System.out.println("test WrongLeVsP2 DateNaissance READ_DATA, ended PASS ...");
			else
				System.out.println("test WrongLeVsP2 DateNaissance READ_DATA, ended FAIL ...");
		} else
			System.out.println("test WrongLeVsP2 DateNaissance READ_DATA, ended FAIL (Store Data Failed) ...");
		System.out.println("**************************************");
	}

	private static void testWrongLeVsP2_ID_READ_DATA() {
		System.out.println("**************************************");
		System.out.println("test WrongLeVsP2 ID READ_DATA, start ...");
		int cla = 0x00;
		int ins = 0x10;
		int p1 = 0x00;
		int p2 = 0x04;
		int le = 0x07;
		byte[] ID = { 23, 1, 2, 3, 4, 5, 6, 7 };

		// Store Date de naissance
		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, ID);
		System.out.println("APDU STORE_DATA ID ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " " + String.format("%02X", ID.length));
		for (int i = 0; i < ID.length; i++)
			System.out.print(" " + String.format("%02X", ID[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));
		if (0x9000 == sw) {
			System.out.println("Read Data WrongLeVsP2 ID...");
			System.out.println("APDU READ_DATA ...");
			ins = 0x20;
			commandAPDU = new CommandAPDU(cla, ins, p1, p2, le);
			response = simulator.transmitCommand(commandAPDU);
			sw = response.getSW();
			byte[] ReadDate = response.getData();
			if (ReadDate.length != 0) {
				for (int i = 0; i < ReadDate.length; i++)
					System.out.print(" " + String.format("%02X", ReadDate[i]));
				System.out.println("");
				System.out.println("SW : " + Integer.toHexString(sw));
				System.out.println("test WrongLeVsP2 ID READ_DATA, ended FAIL (wrong data sent back) ...");
			} else {
				System.out.println("");
				System.out.println("SW : " + Integer.toHexString(sw));
			}

			// Check response status word
			if (0x6C08 == sw)
				System.out.println("test WrongLeVsP2 ID READ_DATA, ended PASS ...");
			else
				System.out.println("test WrongLeVsP2 ID READ_DATA, ended FAIL ...");
		} else
			System.out.println("test WrongLeVsP2 ID READ_DATA, ended FAIL (Store Data Failed) ...");
		System.out.println("**************************************");
	}

	private static void testWrongCLA_UPDATE_DATE() {
		System.out.println("**************************************");
		System.out.println("test Wrong CLA UPDATE_DATE, start ...");
		int cla = 0x80;
		int ins = 0x30;
		int p1 = 0x05;
		int p2 = 0x05;
		byte[] data = { 7, 5, 7, 8, 2, 1, 2, 3, 7, 5, 7, 8, 2, 1, 2, 3 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU UPDATE_DATE ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");

		System.out.println("SW : " + Integer.toHexString(sw));
		// Check response status word
		if (0x6E00 == sw)
			System.out.println("test Wrong CLA UPDATE_DATE, ended PASS ...");
		else
			System.out.println("test Wrong CLA UPDATE_DATE, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongP1_UPDATE_DATE() {
		System.out.println("**************************************");
		System.out.println("test WrongP1 UPDATE_DATE, start...");
		int cla = 0x84;
		int ins = 0x30;
		int p1 = 0x01;
		int p2 = 0x03;
		byte[] data = { 7, 5, 7, 8, 2, 1, 2, 3, 5 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU UPDATE_DATE ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x6B00 == sw)
			System.out.println("test WrongP1 UPDATE_DATE, ended PASS ...");
		else
			System.out.println("test WrongP1 UPDATE_DATE, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongP2_UPDATE_DATE() {
		System.out.println("**************************************");
		System.out.println("test WrongP2 UPDATE_DATE, start...");
		int cla = 0x84;
		int ins = 0x30;
		int p1 = 0x00;
		int p2 = 0x02;
		byte[] data = { 7, 5, 7, 8 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU UPDATE_DATE ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x6B00 == sw)
			System.out.println("test WrongP2 UPDATE_DATE, ended PASS ...");
		else
			System.out.println("test WrongP2 UPDATE_DATE, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongLc_UPDATE_DATE() {
		System.out.println("**************************************");
		System.out.println("test WrongLc UPDATE_DATE, start...");
		int cla = 0x84;
		int ins = 0x30;
		int p1 = 0x00;
		int p2 = 0x03;
		byte[] data = { 7, 5, 7, 8 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU UPDATE_DATE ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x6700 == sw)
			System.out.println("test WrongLc UPDATE_DATE, ended PASS ...");
		else
			System.out.println("test WrongLc UPDATE_DATE, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongMAC_UPDATE_DATE() {
		System.out.println("**************************************");
		System.out.println("test WrongMAC UPDATE_DATE, start...");
		int cla = 0x84;
		int ins = 0x30;
		int p1 = 0x00;
		int p2 = 0x03;
		byte[] data = { 7, 5, 7, 8, 0, 0, 0, 0 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU UPDATE_DATE ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x6982 == sw)
			System.out.println("test WrongMAC UPDATE_DATE, ended PASS ...");
		else
			System.out.println("test WrongMAC UPDATE_DATE, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testGoodData_UPDATE_DATE() {
		System.out.println("**************************************");
		System.out.println("test GoodData UPDATE_DATE, start...");
		int cla = 0x84;
		int ins = 0x30;
		int p1 = 0x00;
		int p2 = 0x03;
		byte[] data = { 7, 5, 7, 8, 0, 0, 0, 0 };
		byte[] MAC = { 0, 0, 0, 0, 0, 0, 0, 0 };

		m_encryptCipherMAC.doFinal(data, (short) 0, (short) 8, MAC, (short) 0);
		Util.arrayCopyNonAtomic(MAC, (short) 0, data, (short) 4, (short) 4);

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU UPDATE_DATE ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x9000 == sw)
			System.out.println("test GoodData UPDATE_DATE, ended PASS ...");
		else
			System.out.println("test GoodData UPDATE_DATE, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongCLA_UPDATE_ID() {
		System.out.println("**************************************");
		System.out.println("test Wrong CLA UPDATE_ID, start ...");
		int cla = 0x80;
		int ins = 0x40;
		int p1 = 0x05;
		int p2 = 0x05;
		byte[] data = { 7, 5, 7, 8, 2, 1, 2, 3, 7, 5, 7, 8, 2, 1, 2, 3 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU UPDATE_ID ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");

		System.out.println("SW : " + Integer.toHexString(sw));
		// Check response status word
		if (0x6E00 == sw)
			System.out.println("test Wrong CLA UPDATE_ID, ended PASS ...");
		else
			System.out.println("test Wrong CLA UPDATE_ID, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongP1_UPDATE_ID() {
		System.out.println("**************************************");
		System.out.println("test WrongP1 UPDATE_ID, start...");
		int cla = 0x84;
		int ins = 0x40;
		int p1 = 0x01;
		int p2 = 0x04;
		byte[] data = { 7, 5, 7, 8, 2, 1, 2, 3, 5 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU UPDATE_ID ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x6B00 == sw)
			System.out.println("test WrongP1 UPDATE_ID, ended PASS ...");
		else
			System.out.println("test WrongP1 UPDATE_ID, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongP2_UPDATE_ID() {
		System.out.println("**************************************");
		System.out.println("test WrongP2 UPDATE_ID, start...");
		int cla = 0x84;
		int ins = 0x40;
		int p1 = 0x00;
		int p2 = 0x03;
		byte[] data = { 7, 5, 7, 8 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU UPDATE_ID ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x6B00 == sw)
			System.out.println("test WrongP2 UPDATE_ID, ended PASS ...");
		else
			System.out.println("test WrongP2 UPDATE_ID, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testWrongLc_UPDATE_ID() {
		System.out.println("**************************************");
		System.out.println("test WrongLc UPDATE_ID, start...");
		int cla = 0x84;
		int ins = 0x40;
		int p1 = 0x00;
		int p2 = 0x04;
		byte[] data = { 7, 5, 7, 8 };

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU UPDATE_ID ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x6700 == sw)
			System.out.println("test WrongLc UPDATE_ID, ended PASS ...");
		else
			System.out.println("test WrongLc UPDATE_ID, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testGoodData_UPDATE_ID() {
		System.out.println("**************************************");
		System.out.println("test GoodData UPDATE_ID, start...");
		int cla = 0x84;
		int ins = 0x40;
		int p1 = 0x00;
		int p2 = 0x04;
		byte[] clearData = { 7, 5, 7, 8, 1, 2, 3, 9 };
		byte[] data = new byte[8];
		m_encryptCipher.doFinal(clearData, (short) 0, (short) 8, data, (short) 0);

		CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, data);
		System.out.println("APDU UPDATE_ID ...");
		ResponseAPDU response = simulator.transmitCommand(commandAPDU);
		int sw = response.getSW();
		System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
				+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
				+ String.format("%02X", data.length));
		for (int i = 0; i < data.length; i++)
			System.out.print(" " + String.format("%02X", data[i]));
		System.out.println("");
		System.out.println("SW : " + Integer.toHexString(sw));

		// Check response status word
		if (0x9000 == sw) {
			// Read back ID to check it is correctly stored
			System.out.println("Read ID Data to check...");
			System.out.println("APDU READ_DATA ...");
			cla = 0x00;
			ins = 0x20;
			int le = 8;
			commandAPDU = new CommandAPDU(cla, ins, p1, p2, le);
			response = simulator.transmitCommand(commandAPDU);
			sw = response.getSW();
			byte[] ReadDate = response.getData();
			if (ReadDate.length == 8) {
				System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
						+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
						+ String.format("%02X", ReadDate.length));
				for (int i = 0; i < ReadDate.length; i++)
					System.out.print(" " + String.format("%02X", ReadDate[i]));
				System.out.println("");
				System.out.println("SW : " + Integer.toHexString(sw));

				if (Util.arrayCompare(ReadDate, (short) 0, clearData, (short) 0, (short) ReadDate.length) == 0) {
					System.out.println("Data Read back is OK (correctly deciphered and stored)...");
					System.out.println("test GoodData UPDATE_ID, ended PASS ...");
				} else {
					System.out.println("Data Read back is FAIL ...");
					System.out.println("test GoodData UPDATE_ID, ended FAIL ...");
				}
			} else {
				if (ReadDate.length != 0) {
					System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins)
							+ " " + String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
							+ String.format("%02X", ReadDate.length));
					for (int i = 0; i < ReadDate.length; i++)
						System.out.print(" " + String.format("%02X", ReadDate[i]));
					System.out.println("");
					System.out.println("SW : " + Integer.toHexString(sw));
				} else {
					System.out.println("");
					System.out.println("SW : " + Integer.toHexString(sw));
				}
				System.out.println(
						"test GoodData UPDATE_ID, ended FAIL (data read back length is not correct: lenght is not equal to 8)!");
			}
		} else
			System.out.println("test WrongMAC UPDATE_ID, ended FAIL ...");
		System.out.println("**************************************");
	}

	private static void testINSNotSupported() {
		System.out.println("**************************************");
		System.out.println("test INSNotSupported, start...");
		int cla = 0x00;
		int p1 = 0x00;
		int p2 = 0x04;
		int le = 1;
		boolean failFlag = false;

		for (int ins = 0; ins < 0x100; ins++) {
			if ((ins != 0x10) && (ins != 0x20) && (ins != 0x30) && (ins != 0x40)) {
				CommandAPDU commandAPDU = new CommandAPDU(cla, ins, p1, p2, le);
				ResponseAPDU response = simulator.transmitCommand(commandAPDU);
				int sw = response.getSW();
				System.out.print("APDU Command : " + String.format("%02X", cla) + " " + String.format("%02X", ins) + " "
						+ String.format("%02X", p1) + " " + String.format("%02X", p2) + " "
						+ String.format("%02X", le));
				System.out.println("");
				System.out.println("SW : " + Integer.toHexString(sw));
				if (0x6D00 != sw) {
					failFlag = true;
					System.out.println("testINSNotSupported FAILED, INS = " + String.format("%02X", ins)
							+ " Seems to be supported!");
				}
			}
		}
		if (!failFlag)
			System.out.println("test INSNotSupported, ended PASS ...");
		System.out.println("**************************************");

	}

}

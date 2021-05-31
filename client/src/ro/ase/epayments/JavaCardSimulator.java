package ro.ase.epayments;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import ro.ase.epayments.applets.HwApplet;

import java.util.Arrays;

public class JavaCardSimulator {

    // Fields region
    private static final AID APPLET_AID = new AID("A0A1A2A3A4".getBytes(), (short) 0, (byte) 10);
    private final JavaxSmartCardInterface simulator;

    public JavaCardSimulator() {
        this.simulator = new JavaxSmartCardInterface();
        simulator.installApplet(APPLET_AID, HwApplet.class);
        simulator.selectApplet(APPLET_AID);
    }

    public byte[] encrypt(final byte[] plaintext) {
        if (plaintext.length < 16) {
            throw new RuntimeException("Bad args");
        }

        final var noSteps = plaintext.length % 16 == 0
                ? plaintext.length / 16 - 1
                : plaintext.length / 16;

        final var result = new byte[(noSteps + 1) * 16];

        // init encrypt
        var commandArray = new byte[22];
        commandArray[0] = (byte) 0x80;  // CLA
        commandArray[1] = 0x50;         // INS
        commandArray[2] = 0x01;         // P1 init encrypt
        commandArray[3] = 0x00;         // P2 is final
        commandArray[4] = 0x10;         // Lc

        for (var idx = 5; idx < 21; ++idx) {
            commandArray[idx] = plaintext[idx - 5];
        }

        commandArray[21] = 0x10;        // Le

        var tempBuffer = simulator.transmitCommand(commandArray);
        System.arraycopy(tempBuffer, 0, result, 0, 16);

        for (var i = 1; i < noSteps; ++i) {
            commandArray[2] = 0x00;
            for (var idx = 5; idx < 21; ++idx) {
                commandArray[idx] = plaintext[i * 16 + idx - 5];
            }

            tempBuffer = simulator.transmitCommand(commandArray);
            System.arraycopy(tempBuffer, 0, result, i * 16, 16);
        }

        final var lastBlockSize = plaintext.length % 16 == 0
                ? 16
                : plaintext.length % 16;

        commandArray[2] = 0x00;
        commandArray[3] = 0x01;
        commandArray[4] = (byte) lastBlockSize;
        for (var idx = 5; idx < 5 + lastBlockSize; ++idx) {
            commandArray[idx] = plaintext[(noSteps * 16) + idx - 5];
        }
        commandArray[5 + lastBlockSize] = 0x10;

        tempBuffer = simulator.transmitCommand(Arrays.copyOf(commandArray, 5 + lastBlockSize + 1));
        System.arraycopy(tempBuffer, 0, result, noSteps * 16, 16);

        return result;
    }

    public byte[] decrypt(final byte[] ciphertext) {
        if (ciphertext.length < 16) {
            throw new RuntimeException("Bad args");
        }

        final var noSteps = ciphertext.length / 16 - 1;
        final var plaintext = new byte[ciphertext.length];

        // init decrypt
        var commandArray = new byte[22];
        commandArray[0] = (byte) 0x80;  // CLA
        commandArray[1] = 0x60;         // INS
        commandArray[2] = 0x01;         // P1 init encrypt
        commandArray[3] = 0x00;         // P2 is final
        commandArray[4] = 0x10;         // Lc

        for (var idx = 5; idx < 21; ++idx) {
            commandArray[idx] = ciphertext[idx - 5];
        }

        commandArray[21] = 0x10;        // Le

        var tempBuffer = simulator.transmitCommand(commandArray);
        System.arraycopy(tempBuffer, 0, plaintext, 0, 16);

        for (var i = 1; i < noSteps; ++i) {
            commandArray[2] = 0x00;
            for (var idx = 5; idx < 21; ++idx) {
                commandArray[idx] = ciphertext[i * 16 + idx - 5];
            }

            tempBuffer = simulator.transmitCommand(commandArray);
            System.arraycopy(tempBuffer, 0, plaintext, i * 16, 16);
        }

        commandArray[2] = 0x00;
        commandArray[3] = 0x01;
        for (var idx = 5; idx < 21; ++idx) {
            commandArray[idx] = ciphertext[(noSteps * 16) + idx - 5];
        }
        tempBuffer = simulator.transmitCommand(commandArray);
        System.arraycopy(tempBuffer, 0, plaintext, noSteps * 16, 16);

        // check if it is has any empty bytes
        for (var i = plaintext.length - 1; i > 0; --i) {
            if (plaintext[i] != 0x00) {
                if (i == plaintext.length - 1) return plaintext;
                else return Arrays.copyOf(plaintext, i + 1);
            }
        }

        return plaintext;
    }
}
